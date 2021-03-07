
//! This module contains the primary object, `NickTracker` that provides the 
//! features of the addon and implements the commands and handlers.
//! 

use regex::Regex;
use serde_json::Value;
use serde_json::from_str as parse_json;
use std::collections::HashSet;
use std::time::Duration;
use std::u32;
use ureq::Agent;
use ureq::AgentBuilder;

use crate::nick_data::*;
use crate::tor::*;
use crate::tracker_error::*;
use crate::dll_entry_points::*;

use hexchat_api::*;
use TrackerError::*;

// Regular expressions used to find the IP in the host string.
const IPV6_EXPR      : &str  =  "(?:[0-9a-fA-F]+:){7}[0-9a-fA-F]+|\
                                 (?:[0-9a-fA-F]+-){7}[0-9a-fA-F]+";
const IPV4_EXPR      : &str  = r"\d+\.\d+\.\d+\.\d+|\d+-\d+-\d+-\d+";

// Expression used in re.sub() calls below to delimit the IP address.
// Matches (non)standard delimiters and leading 0's in address parts.
// r"(?:^|\.|-|:)0*(?!\.|-|:|$)" won't work because Rust regex doesn't have
// lookahead. So I replaced the neg lookahead with a simple \B.
const DLIM_EXPR      : &str  = r"(?:^|\.|-|:)0*\b";

// How long to wait for the IP geolaction server to respond.
const SERVER_TIMEOUT : u64   = 5;

const MAX_QUEUED_TASKS : usize = 10;

/// Channel data, a tuple of two strings. The first represeting the name of the
/// network, and the second is the name of the channel.
///
type ChanData = (String, String);

/// The primary struct/class of the tracker. It provides handlers for the
/// registered commands.
///
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
    /// Creates a new `NickTracker` - this is called in `dll_entry_points.rs`
    /// then the methods below are wrapped and registered as the user visible
    /// commands in Hexchat.
    /// 
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
    
    /// "Activates" the window the user currently is interacting with.
    ///
    fn activate(&mut self) {
        let chan_data = self.get_chan_data();
        self.chan_set.insert(chan_data);
        self.write("🔎\t\x0311Nick Tracker enabled for this channel.");
    }
    
    /// "Deactivates" the window the user is currently interacting with.
    ///
    fn deactivate(&mut self) {
        let chan_data = self.get_chan_data();
        self.chan_set.remove(&chan_data);
        self.write("🔎\t\x0311Nick Tracker disabled for this channel.");
    }
    
    /// Determines if the current window has been activated.
    ///
    fn is_active(&self) -> bool {
        let chan_data = self.get_chan_data();
        self.chan_set.contains(&chan_data)
    }
    
    /// Outputs text to the current active Hexchat window.
    ///
    pub (crate)
    fn write(&self, msg: &str) {
        self.hc.print(msg);
    }
    
    /// Like `write()` but takes a `Context` reference which sends the text
    /// to the window associated with that context.
    ///
    #[allow(dead_code)]
    pub (crate)
    fn write_ctx(&self, msg: &str, ctx: &Context) {
        if ctx.print(msg).is_err() {
            self.hc.print("⚠️\t\x0313Context grab failed for this message...");
            self.hc.print(msg);
        }
    }
    
    /// Like `write_ctx()` but is save to invoke from other threads with a
    /// `ThreadSafeContext` to direct output to the window associated with the
    /// context.
    /// # Arguments
    /// * `msg` - The message to print.
    /// * `ctx` - The thread-safe context which directs the text output to its 
    ///           associated window.
    ///
    pub (crate)
    fn write_ts_ctx(&self, msg: &str, ctx: &ThreadSafeContext) {
        if ctx.print(msg).is_err() {
            self.hc.print("⚠️\t\x0313Context grab failed for this message...");
            self.hc.print(msg);
        }
    }
    
    /// Returns the `network` name and `channel` name of the currently active
    /// window.
    /// # Returns
    /// * A tuple that holds the network and channel names as strings, in that
    ///   order.
    ///
    fn get_chan_data(&self) -> (String, String) {
        // These operations shouldn't fail if this is executed from main thread.
        let network = self.hc.get_info("network").unwrap();
        let channel = self.hc.get_info("channel").unwrap();
        (network, channel)
    }
    
    /// Implements the `/DBTOGGLE` command. If the current window is active,
    /// it sets it inactive - and vice versa.
    ///
    pub (crate)
    fn on_cmd_dbtoggle(&mut self, 
                       word      : &[String], 
                       _word_eol : &[String]
                      ) -> Eat 
    {
        use FieldValue as FV;
        
        if word.len() == 1 {
            // Simple case - just toggle the current channel.
            if self.is_active() {
                self.deactivate();
            } else {
                self.activate();
            }
        } else if (word.len() > 1 && word[1].to_lowercase() == "all")
                   && (word.len() == 2 || (word.len() == 3
                        && ["on", "off"].contains(&word[2].to_lowercase()
                                                          .as_str())))
        {
            // This is some version of ALL [ON|OFF], where ON/OFF are optional.
            
            // `one_way == true` means flip *all* ON or OFF - don't just toggle.
            // If `one_way == false`, then each open channel is flipped the 
            // opposite of its current state individually.
            let one_way = word.len() == 3;
            let all_on  = one_way && word[2].to_lowercase().as_str() == "on";
            
            if let Some(list) = ListIterator::new("channels") {
                for item in list {
                    if let Ok(FV::StringVal(network)) 
                                    = item.get_field("network") {
                            
                    if let Ok(FV::StringVal(channel)) 
                                    = item.get_field("channel") {
                                    
                        if !channel.starts_with('#') {
                            continue;
                        }
                            
                        let chan_data = (network.clone(), channel.clone());
                         
                        // Channels already in the desired state are skipped
                        // if this is a `one_way == true` operation.   
                        
                        if !(self.chan_set.contains(&chan_data)
                                || one_way && !all_on) 
                        {
                            self.chan_set.insert(chan_data);
                            self.write(
                                &format!("🔎\t\x0311\
                                         Nick Tracker enabled for ({}/{}).",
                                         network, channel));        
                                         
                        } else if self.chan_set.contains(&chan_data) 
                                && !(one_way && all_on) {
                            self.chan_set.remove(&chan_data);
                            self.write(
                                &format!("🔎\t\x0311\
                                         Nick Tracker disabled for ({}/{}).",
                                         network, channel));        
                        }
                    }}
                }
                // TODO - The logic in this function is kind of "windey". 
                //        It might be possible to simplify it and clean it up
                //        a bit.
            }
        } else {
            self.write("💡\t\x0311Usage: DBTOGGLE [ALL [ON|OFF]]");
        }
        Eat::All
    }
    
    /// Implements the `/IPLOOKUP` user command. This attempts to get the
    /// geolocation data for the provided IP.
    /// # Arguments
    /// * `word`     - The arguments provided from user input.
    /// * `word_eol` - Catenations of `word`.
    /// # Output
    /// * Provides details on the location associated with the IP and gives a
    ///   clickable web link that opens a Google Maps page zoomed in on that
    ///   location.
    ///
    pub (crate)
    fn on_cmd_ip_lookup(&mut self, 
                        word      : &[String], 
                        _word_eol : &[String]
                       ) -> Eat  
    {
        if word.len() != 2 {
            self.write("💡\t\x0311Usage: IPLOOKUP <IP>");
            return Eat::All;
        }
        if num_queued_tasks() > MAX_QUEUED_TASKS {
            self.write("⚠️\t\x0313Too many outstanding tasks.");
            return Eat::All;
        }
        let ip_addr = self.normalize_ip_addr(&word[1]);
        let me      = self.clone();
        let hc      = me.hc.threadsafe();
        let cx      = hc.get_context().expect("Context grab shouldn't fail.");    
        
        thread_task(move || {
            match me.get_ip_addr_info(&ip_addr) {
                Ok(ip_info) => {
                    let [_ip, city, 
                         region, country,
                         isp, _lat, _lon, link] = &ip_info;
                         
                    me.write_ts_ctx(
                        &format!("🌎\t\x0311IPLOOKUP ({}): {}, {} ({}) [{}]",
                                 ip_addr, city, region, country, isp),
                        &cx
                    );
                    me.write_ts_ctx(&format!("\x0311    MAP: {}", link), &cx);
                },
                Err(err) => {
                    me.write_ts_ctx(
                        &format!("🌎\t\x0313IPLOOKUP ({}): failed. {}", 
                                 &ip_addr, err), &cx);
                },
            }
        });
        Eat::All
    }
    
    /// Implements the `/DBUPDATE` user command. Goes through all the users in
    /// the channel and adds their info to the database.
    ///
    pub (crate)
    fn on_cmd_dbupdate(&mut self, 
                        word      : &[String], 
                        _word_eol : &[String]
                       ) -> Eat  
    {
        if word.len() > 1 {
            self.write("💡\t\x0311Usage: DBUPDATE <takes no arguments>");
            return Eat::All;
        }
        if num_queued_tasks() > MAX_QUEUED_TASKS {
            self.write("⚠️\t\x0313Too many outstanding tasks.");
            return Eat::All;
        }
        let me = self.clone();
        let hc = self.hc.threadsafe();
        let cx = hc.get_context().expect("Context grab shouldn't fail.");
        
        thread_task(move || {
            #[allow(clippy::single_match)]
            match || -> Result<(), TrackerError> {

                cx.print("🤔\t\x0311DBUPDATE:")?;
            
                let mut count = 0;
                let user_list = cx.list_get("users").tor()?;

                for user in &user_list {
                    let [nick, 
                         channel, 
                         host, 
                         account, 
                         address, 
                         network] = me.get_user_info_ts(&user, &cx)?;
                         
                    if me.nick_data.update(&nick,    &channel, &host,
                                           &account, &address, &network)
                    {
                        cx.print(
                            &format!("\x0311+ new record added for user \
                                      \x0309\x02{}.", &nick)
                        )?;
                        count = 1;
                    } else {
                        if count % 200 == 0 {
                            cx.print("\x0311- processing...")?;
                        }
                        count += 1;
                    }
                }
                cx.print("\x0311DBUPDATE Done.\n")?;
                Ok(())
            }() {
                Err(err) => {
                    me.write_ts_ctx(
                        &format!("⚠️\t\x0313Error during update: {}", err),
                        &cx
                    );
                },
                _ => (),
            }
        });
        Eat::All
    }
    
    /// Implements `/DBWHO` user command. Given a nickname, it will list
    /// records that are likely related to it. For instance, past nicks they
    /// used, different locations they've logged in from, etc.
    ///
    pub (crate)
    fn on_cmd_dbwho(&mut self,
                    word      : &[String],
                    _word_eol : &[String]
                   ) -> Eat
    {
        if word.len() != 2 {
            self.write("💡\t\x0311Usage: DBWHO <nick>");
            return Eat::All;
        }
        if num_queued_tasks() > MAX_QUEUED_TASKS {
            self.write("⚠️\t\x0313Too many outstanding tasks.");
            return Eat::All;
        }
        let who    = word[1].clone();
        let who_lc = word[1].to_lowercase();
        
        let me = self.clone();
        let hc = self.hc.threadsafe();
        let cx = hc.get_context().expect("Context grab shouldn't fail.");
        
        thread_task(move || {
            #[allow(clippy::single_match)]
            match || -> Result<(), TrackerError> {
                cx.print(&format!("🕵️\t\x0311DBWHO: \x0309\x02{}", who))?;
                let mut found = false;
                let     users = cx.list_get("users").tor()?;
                
                for user in &users {
                    let account = user.get_field("account").tor()?;
                    let nick    = user.get_field("nick").tor()?;
                    
                    if who_lc == nick.to_lowercase()    || 
                       who_lc == account.to_lowercase() 
                    {
                        let info = me.get_user_info_ts(&user, &cx)?;
                        let [nick, _channel, 
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
                        &format!("⚠️\t\x0313Nickname {} not currently in {}.", 
                                 who, channel), &cx);
                }
                Ok(())
            }() {
                Err(err) => {
                    me.write_ts_ctx(
                        &format!("⚠️\t\x0313Error during update: {}", err),
                        &cx
                    );
                },
                _ => {},
            }
        });
        Eat::All
    }
    
    /// Implements the callback for the `Join` text event. Gathers the user's
    /// info and adds it to the database.
    ///
    pub (crate)
    fn on_user_join(&mut self, 
                    word: &[String]
                   ) -> Eat 
    {
        if !self.is_active() {
            return Eat::None;
        }
        if num_queued_tasks() > MAX_QUEUED_TASKS {
            return Eat::All;
        }
        let account = if word.len() > 3 { 
            word[3].clone() 
        } else { 
            String::new()
        };
        
        let (nick, channel, host) = (word[0].clone(), word[1].clone(),
                                     word[2].clone());

        let address = self.normalize_ip_addr(&host);
        let network = self.hc.get_info("network").unwrap();
        let hc      = self.hc.threadsafe();
        let me      = self.clone();
        let cx      = hc.get_context().unwrap();
        
        thread_task(move || {
            me.write_ts_ctx(&format!("🕵️\t\x0311USER JOINED: \x0309\x02{}", 
                                     nick), &cx);
            
            me.nick_data.update(&nick,    &channel, &host, 
                                &account, &address, &network);
                                
            me.nick_data.print_related(&nick,    &host,    &account, 
                                       &address, &network, &me, &cx);
        });
        Eat::None
    }
    
    /// Implements the handler for the `Quit` text event. Does nothing 
    /// currently.
    ///
    pub (crate)
    fn on_user_quit(&self, _word: &[String]) -> Eat
    {
        if !self.is_active() {
            Eat::None
        } else {
            Eat::All
        }
    }
    
    /// Implements the handler for the `Change Nick` text event. The user's
    /// current nick and the nick they changed to are now associated with
    /// other records in the database.
    ///
    pub (crate)
    fn on_user_change_nick(&self, word: &[String]) -> Eat 
    {
        if !self.is_active() {
            Eat::None
        } else {
            if num_queued_tasks() > MAX_QUEUED_TASKS {
                return Eat::All;
            }
            let old_nick = word[0].clone();
            let new_nick = word[1].clone();
            
            let me = self.clone();
            let hc = self.hc.threadsafe();
            let cx = hc.get_context().unwrap();
            
            thread_task(move || {
                #[allow(clippy::single_match)]
                match || -> Result<(), TrackerError> {
                
                    for user in cx.list_get("users").tor()? {

                        let nick = user.get_field("nick").tor()?;
                        
                        if nick == old_nick || nick == new_nick {
                            let [_nick, 
                                 channel, 
                                 host, 
                                 account, 
                                 address, 
                                 network] = me.get_user_info_ts(&user, 
                                                                &cx)?;
                                 
                            me.nick_data.update(&new_nick, &channel, 
                                                &host,     &account,  
                                                &address,  &network);
                        }
                    }
                    Ok(())
                }() {
                    Err(err) => {
                        me.write(&format!("⚠️\t\x0313{}", err));
                    },
                    _ => {},
                }
            });
            Eat::All
        }
    }

    /// A helper function to gather the Hexchat list field information for a 
    /// user. It constructs a slice containing the  'nick', 'account',
    /// 'host', etc.
    ///
    #[allow(dead_code)]
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
            self    .normalize_ip_addr 
                                 ( &host   ),
            context .get_info    ("network") .tor()?
           ])
    }
    
    /// This is a thread-safe version of `get_user_info()`.
    ///
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
            self    .normalize_ip_addr 
                                 ( &host   ),
            context .get_info    ("network") .tor()?
           ])
    }
    
    /// Attempts to extract a normalized IP (v4 or v6) from the 'host' string
    /// given.
    /// # Arguments
    /// * `host` - A user's host string as taken from the Hexchat "user" list
    ///            (i.e., `user_list_item.get_field("host")`).
    /// # Returns
    /// * A normalized IPv4 or IPv6 address suitable for database entry, or
    ///   use in queries.
    ///
    fn normalize_ip_addr(&self, host: &str) -> String {
    
        if let Some(m) = self.ipv6_expr.find(host) {
       
            let addr = m.as_str().to_lowercase();
    
            addr.split(|c: char| ".-:".contains(c))
                .map(|s| u32::from_str_radix(s, 16).unwrap_or(0))
                .map(|i| format!("{:x}", i))
                .collect::<Vec<_>>()
                .join(":")
            
        } else if let Some(m) = self.ipv4_expr.find(host) {
        
            let addr = m.as_str().to_lowercase();
            addr.split(|c: char| ".-:".contains(c))
                .map(|s| u32::from_str_radix(s, 10).unwrap_or(0))
                .map(|i| format!("{:?}", i))
                .collect::<Vec<_>>()
                .join(".")

        } else {
            String::new()
        }
    }
    
    /// Accesses a geolocation web service to get the location data for
    /// an IP. If the IP has been looked up before, it can be retrieved from
    /// the database without having to access the web service.
    ///
    pub (crate)
    fn get_ip_addr_info(&self, 
                        ip_addr: &str
                       ) -> Result<[String;8], TrackerError> 
    {
        const LATITUDE_IDX   : usize = 5;
        const LONGITUDE_IDX  : usize = 6;
        const MAP_ZOOM_LEVEL : i32   = 6;
        
        fn add_link(ip_info: &mut [String]) {
            let lat    = &ip_info[LATITUDE_IDX];
            let lon    = &ip_info[LONGITUDE_IDX];
            let link   = format!("http://maps.google.com/maps/place/\
                                  {},{}/@{},{},{}z",
                                 lat, lon, lat, lon, MAP_ZOOM_LEVEL);
            ip_info[7] = link;
        }

        if let Ok(mut ip_info) = self.nick_data.get_ip_addr_info(ip_addr) {
            add_link(&mut ip_info);
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

                    add_link(&mut info);

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




















