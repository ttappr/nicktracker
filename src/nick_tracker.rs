
#![allow(unused_variables, dead_code, unused_imports)]

use regex::Regex;
use serde_json::Value;
use serde_json::from_str as parse_json;
use std::collections::HashSet;
use std::convert::From;
use std::error::Error;
use std::fmt;
use std::thread;
use std::time::Duration;
use ureq::Agent;
use ureq::AgentBuilder;

use crate::nick_data::*;
use crate::tor::*;
use crate::tracker_error::*;

use hexchat_api::*;
use TrackerError::*;
use UserData::*;

// Regular expressions used to find the IP in the host string.
const IPV6_EXPR      : &str  =  "(?:[0-9a-fA-F]+:){7}[0-9a-fA-F]+|\
                                 (?:[0-9a-fA-F]+-){7}[0-9a-fA-F]+";
const IPV4_EXPR      : &str  = r"\d+\.\d+\.\d+\.\d+|\d+-\d+-\d+-\d+";

// Expression used in re.sub() calls below to delimit the IP address.
// Matches (non)standard delimiters and leading 0's in address parts.
// r"(?:^|\.|-|:)0*(?!\.|-|:|$)" won't work because Rust regex doesn't have
// lookahead. So I replaced the neg lookahead with a simple \B.
const DLIM_EXPR      : &str  = r"(?:^|\.|-|:)0*\B";

// How long to wait for the IP geolaction server to respond.
const SERVER_TIMEOUT : u64   = 5;

/// Channel data, a tuple of two strings. The first represeting the name of the
/// network, and the second is the name of the channel.
///
type ChanData = (String, String);

/// Tracks the channels that have been activated for tracking. Any channel that
/// has been activated should have an entry in this set. The entries are tuples
/// of the channel's network name and channel name.
///
type ChanSet  = HashSet<ChanData>;

#[derive(Clone)]
pub (crate) 
struct NickTracker {
    hc          : &'static Hexchat,
    ipv6_expr   : Regex,
    ipv4_expr   : Regex,
    dlim_expr   : Regex,
    chan_set    : HashSet::<ChanData>,
    nick_data   : NickData,
    http_agent  : Agent,
}

impl NickTracker {
    pub (crate)
    fn new(hc: &'static Hexchat) -> Self {
        NickTracker { 
            hc,
            ipv6_expr   : Regex::new(IPV6_EXPR).unwrap(),
            ipv4_expr   : Regex::new(IPV4_EXPR).unwrap(),
            dlim_expr   : Regex::new(DLIM_EXPR).unwrap(),
            chan_set    : HashSet::<ChanData>::new(),
            nick_data   : NickData::new(hc),
            http_agent  : AgentBuilder::new()
                          .timeout_read(
                              Duration::from_secs(SERVER_TIMEOUT)
                          ).build(),
        }
    }
    pub (crate)
    fn hello(&self, 
             hc         : &Hexchat, 
             word       : &[String], 
             word_eol   : &[String], 
             user_data  : &mut UserData
            ) -> Eat
    {
        hc.print("Hello, world!");
        Eat::All
    }
    fn activate(&mut self) {
        let chan_data = self.get_chan_data();
        self.chan_set.insert(chan_data);
        self.hc.print("🔎\tNick Tracker enabled for this channel.");
    }
    fn deactivate(&mut self) {
        let chan_data = self.get_chan_data();
        self.chan_set.remove(&chan_data);
        self.hc.print("🔎\tNick Tracker disabled for this channel.");
    }
    fn is_active(&self) -> bool {
        let chan_data = self.get_chan_data();
        self.chan_set.contains(&chan_data)
    }
    
    pub (crate)
    fn write(&self, msg: &str) {
        self.hc.print(msg);
    }
    
    pub (crate)
    fn write_ctx(&self, msg: &str, ctx: &Context) {
        if ctx.print(msg).is_err() {
            self.hc.print("⚠️\t\x0313Context grab failed for this message...");
            self.hc.print(msg);
        }
    }
    
    pub (crate)
    fn write_ts_ctx(&self, msg: &str, ctx: &ThreadSafeContext) {
        if ctx.print(msg).is_err() {
            self.hc.print("⚠️\t\x0313Context grab failed for this message...");
            self.hc.print(msg);
        }
    }
    
    fn get_chan_data(&self) -> (String, String) {
        // These operations shouldn't fail if this is executed from main thread.
        let network = self.hc.get_info("network").unwrap();
        let channel = self.hc.get_info("channel").unwrap();
        (network, channel)
    }
    
    pub (crate)
    fn on_cmd_dbtoggle(&mut self, 
                       word     : &[String], 
                       word_eol : &[String]
                      ) -> Eat 
    {
        if self.is_active() {
            self.deactivate();
        } else {
            self.activate();
        }
        Eat::All
    }
    
    pub (crate)
    fn on_cmd_ip_lookup(&mut self, 
                        word     : &[String], 
                        word_eol : &[String]
                       ) -> Eat  
    {
        if word.len() != 2 {
            self.write("💡\tUsage: IPLOOKUP <IP>");
            return Eat::All;
        }
        let ip_addr = word[1].clone();
        let me      = self.clone();
        let hc      = me.hc.threadsafe();
        let cx      = hc.get_context().expect("Context grab shouldn't fail.");    
        
        thread::spawn(move || {
            if let Ok(ip_info) = me.get_ip_addr_info(&ip_addr) {
            
                let [ip, city, 
                     region, country,
                     isp, lat, lon, link] = &ip_info;
                     
                me.write_ts_ctx(
                    &format!("🌎\tIPLOOKUP ({}): {}, {} ({}) [{}]",
                             ip_addr, city, region, country, isp),
                    &cx
                );
                me.write_ts_ctx(&format!("    MAP: {}", link), &cx);
                
            } else {
                me.write_ts_ctx(
                    &format!("🌎\tIPLOOKUP ({}): failed.", &ip_addr), &cx);
            }
        });
        Eat::All
    }
    
    pub (crate)
    fn on_cmd_dbupdate(&mut self, 
                        word     : &[String], 
                        word_eol : &[String]
                       ) -> Eat  
    {
        if word.len() > 1 {
            self.write("💡\tUsage: DBUPDATE <takes no arguments>");
            return Eat::All;
        }
        let me = self.clone();
        let hc = self.hc.threadsafe();
        let cx = hc.get_context().expect("Context grab shouldn't fail.");
        
        thread::spawn(move || {
            match || -> Result<(), TrackerError> {

                cx.print("🤔\tDBUPDATE:")?;
            
                let mut count     = 0;
                let     user_list = cx.list_get("users")?;
                
                for user in &user_list {
                    let [nick, 
                         channel, 
                         host, 
                         account, 
                         address, 
                         network] = me.get_user_info_ts(user, &cx)?;
                         
                    if me.nick_data.update(&nick,    &channel, &host,
                                           &account, &address, &network)
                    {
                        cx.print(
                            &format!("+ new record added for user {}.", &nick)
                        )?;
                        count = 1;
                    } else {
                        if count % 200 == 0 {
                            cx.print("- processing...")?;
                        }
                        count += 1;
                    }
                }
                cx.print("DBUPDATE Done.\n")?;
                Ok(())
            }() {
                Err(err) => {
                    me.write_ts_ctx(
                        &format!("⚠️\tError during update: {}", err),
                        &cx
                    );
                },
                _ => (),
            }
        });
        Eat::All
    }
    
    pub (crate)
    fn on_cmd_dbwho(&mut self,
                    word     : &[String],
                    word_eol : &[String]
                   ) -> Eat
    {
        if word.len() != 2 {
            self.write("💡\tUsage: DBWHO <nick>");
            return Eat::All;
        }
        let who    = word[1].clone();
        let who_lc = word[1].to_lowercase();
        
        let me = self.clone();
        let hc = self.hc.threadsafe();
        let cx = hc.get_context().expect("Context grab shouldn't fail.");
        
        thread::spawn(move || {
            match || -> Result<(), TrackerError> {
                cx.print(&format!("🕵️\tDBWHO: {}", who))?;
                let mut found = false;
                let     users = cx.list_get("users")?;
                
                for user in &users {
                    let account = user.get_field("account").tor()?;
                    let nick    = user.get_field("nick").tor()?;
                    
                    if who_lc == nick.to_lowercase()    || 
                       who_lc == account.to_lowercase() 
                    {
                        let info = me.get_user_info_ts(&user, &cx)?;
                        let [nick, channel, 
                             host, account, 
                             address, network] = info;
                             
                        me.nick_data.print_related(&nick,    &host, 
                                                   &account, &address, 
                                                   &network, &me, &cx);
                        found = true;
                        break;
                    }
                }
                if !found {
                    let channel = cx.get_info("channel").tor()?;
                    me.write_ts_ctx(
                        &format!("⚠️\tNickname {} not currently in {}.", 
                                 who, channel), &cx);
                }
                Ok(())
            }() {
                Err(err) => {
                    me.write_ts_ctx(
                        &format!("⚠️\tError during update: {}", err),
                        &cx
                    );
                },
                _ => {},
            }
        });
        Eat::All
    }
    
    pub (crate)
    fn on_user_join(&mut self, 
                    word: &[String]
                   ) -> Eat 
    {
        if !self.is_active() {
            return Eat::None;
        }
        let account = if word.len() > 3 { 
            word[3].clone() 
        } else { 
            String::new()
        };
        let (nick, channel, host) = (word[0].clone(), word[1].clone(),
                                     word[2].clone());

        let address = self.get_ip_addr(&host);
        let network = self.hc.get_info("network").unwrap();
        let hc      = self.hc.threadsafe();
        let me      = self.clone();
        let cx      = hc.get_context().unwrap();
        
        thread::spawn(move || {
            me.write_ts_ctx(&format!("🕵️\tUSER JOINED: {}", nick), &cx);
            
            me.nick_data.update(&nick,    &channel, &host, 
                                &account, &address, &network);
                                
            me.nick_data.print_related(&nick,    &host,    &account, 
                                       &address, &network, &me, &cx);
        });
        Eat::None
    }
    
    pub (crate)
    fn on_user_quit(&self, word: &[String]) -> Eat
    {
        if !self.is_active() {
            Eat::None
        } else {
            Eat::All
        }
    }
    
    pub (crate)
    fn on_user_change_nick(&self, word: &[String]) -> Eat 
    {
        if !self.is_active() {
            Eat::None
        } else {
            let (network, channel) = self.get_chan_data();
            let old_nick = &word[0];
            let new_nick = &word[1];
            
            match || -> Result<(), TrackerError> {
                let context = self.hc.get_context().tor()?;
            
                for user in context.list_get("users")? {

                    let nick = user.get_field("nick").tor()?;
                    
                    if &nick == old_nick || &nick == new_nick {
                        let [nick, 
                             channel, 
                             host, 
                             account, 
                             address, 
                             network] = self.get_user_info(&user, &context)?;
                             
                        self.nick_data.update(&new_nick, &channel, &host, 
                                              &account,  &address, &network);
                    }
                }
                Ok(())
            }() {
                Err(err) => {
                    self.write(&format!("⚠️\t{}", err));
                },
                _ => {},
            }
            Eat::All
        }
    }

    fn get_user_info(&self,
                     user    : &hexchat_api::ListIterator,
                     context : &Context
                    ) -> Result<[String;6], TrackerError> 
    {
        let host = user.get_field("host"   ) .tor()?;
        
        Ok([user    .get_field   ("nick"   ) .tor()?,
            context .get_info    ("channel") .tor()?,
            host    .clone(),
            user    .get_field   ("account") .tor()?,
            self    .get_ip_addr ( &host   ),
            context .get_info    ("network") .tor()?
           ])
    }
    
    fn get_user_info_ts(&self,
                        user      : &ThreadSafeListIterator,
                        context   : &ThreadSafeContext
                       ) -> Result<[String;6], TrackerError>
    {
        let host = user.get_field("host"   ) .tor()?;
        
        Ok([user    .get_field   ("nick"   ) .tor()?,
            context .get_info    ("channel") .tor()?,
            host    .clone(),
            user    .get_field   ("account") .tor()?,
            self    .get_ip_addr ( &host   ),
            context .get_info    ("network") .tor()?
           ])
    }
    
    fn get_ip_addr(&self, host: &str) -> String {
    
        if let Some(m) = self.ipv6_expr.find(host) {
        
            let addr = m.as_str().to_lowercase();
            self.dlim_expr.replace(&addr, ":")[1..].to_string()
            
        } else if let Some(m) = self.ipv4_expr.find(host) {
        
            let addr = m.as_str().to_lowercase();
            self.dlim_expr.replace(&addr, ".")[1..].to_string()
            
        } else {
            String::new()
        }
    }
    
    pub (crate)
    fn get_ip_addr_info(&self, 
                        ip_addr: &str
                       ) -> Result<[String;8], TrackerError> 
    {
        const LATITUDE_IDX   : usize = 5;
        const LONGITUDE_IDX  : usize = 6;
        const MAP_ZOOM_LEVEL : i32   = 6;

        if let Ok(ip_info) = self.nick_data.get_ip_addr_info(ip_addr) {
            Ok(ip_info)
        } else {
            let req = format!("http://ip-api.com/json/{}", ip_addr);
            let rsp = self.http_agent.get(&req).call()?;
            
            if rsp.status_text() == "OK" {
                let rsp_text = rsp.into_string()?;
                let rsp_json = parse_json::<Value>(&rsp_text)?;
                
                if rsp_json["status"] == "success" {

                    let mut info = [ip_addr.to_string(),
                                    rsp_json["city"].tor()?,
                                    rsp_json["regionName"].tor()?,
                                    rsp_json["country"].tor()?,
                                    rsp_json["isp"].tor()?,
                                    rsp_json["lat"].tor()?,
                                    rsp_json["lon"].tor()?,
                                    String::new()];

                    let lat  = &info[LATITUDE_IDX];
                    let lon  = &info[LONGITUDE_IDX];
                    let link = format!("http://maps.google.com/maps/place/\
                                        {},{}/@{},{},{}z",
                                       lat, lon, lat, lon, MAP_ZOOM_LEVEL);
                    info[7] = link;
                    
                    self.nick_data.update_ip_addr_info(&info[0], &info[1], 
                                                       &info[2], &info[3], 
                                                       &info[4], &info[5],
                                                       &info[6]);
                    Ok(info)
                } else {
                    // "status" != "success".
                    Err( IPLookupError(
                            format!("IPLOOKUP ERROR ({}): {}", 
                                    rsp_json["query"], 
                                    rsp_json["message"])) )
                }
            } else {
                // status_text() != "OK".
                Err( IPLookupError(
                        format!("IPLOOKUP ERROR: {}", 
                                rsp.status_text())) )
            }
        }
    }
}




















