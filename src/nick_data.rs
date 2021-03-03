
use fallible_iterator::FallibleIterator;
use std::path::Path;
use regex::Regex;
use rusqlite::Connection;
use rusqlite::functions::FunctionFlags;
use rusqlite::NO_PARAMS;
use rusqlite::params;
use rusqlite::Result as SQLResult;
use rusqlite::Rows;
use std::sync::Condvar;
use std::time::Duration;
use std::sync::Mutex;

use hexchat_api::*;

use crate::nick_tracker::*;
use crate::tracker_error::*;
use crate::tor::*;

const DB_BUSY_TIMEOUT: u64 = 5; // Seconds.

#[derive(Clone)]
pub (crate)
struct NickData {
    hc         : &'static Hexchat,
    trunc_expr : Regex,
    path       : String,
}

impl NickData {
    pub (crate)
    fn new(hc: &'static Hexchat) -> Self {
        if let Some(path) = Self::check_database(hc) {
            NickData { 
                hc,
                path, 
                trunc_expr : Regex::new(r"[0-9_\-|]{0,3}$").unwrap(),
            }
        } else {
            panic!("Unable to create new database for Nick Tracker.");
        }
    }
    
    fn check_database(hc: &Hexchat) -> Option<String> {
        let addons_path = Path::new(&hc.get_info("xchatdir")
                                       .unwrap())
                                       .join("addons")
                                       .into_boxed_path();
        let db_path = addons_path.join("nicktracker-db.sqlite3")
                                 .into_boxed_path();
        
        let addons_path_string = addons_path.to_str().unwrap();
        let db_path_string     = db_path.to_str().unwrap();
        
        if !addons_path.exists() {
            if std::fs::create_dir(addons_path).is_err() {
                // Unable to create addons folder for Hexchat.
                return None;
            }
        }
        if !db_path.exists() {
            if let Err(err) = Self::create_database(&db_path_string) 
            {
                // Unable to create database.
                return None
            }
        }
        Some(db_path_string.to_string())
    }
    
    pub (crate)
    fn print_related(&self,
                     nick    : &str,
                     host    : &str,
                     account : &str,
                     address : &str,
                     network : &str,
                     tracker : &NickTracker,
                     context : &ThreadSafeContext)
    {
        const IPV4_LEN: usize = 15;
        const IPV6_LEN: usize = 39;
        
        if let Ok(db_entries) = self.get_db_entries(nick, host, account, 
                                                    address, network)
        {
            for [nick, channel, host, account, address] in &db_entries {
                let mut msg;
                if !address.is_empty() {
                    if let Ok(addr_info) = tracker.get_ip_addr_info(address) {
                        let [ip,  city, region, country,
                             isp, lat,  lon,    link    ] = addr_info;
                        msg = {
                            if ip.len() > IPV4_LEN {
                                format!("\x0313{:-16} {:-39} {}, {} ({}) [{}]",
                                        nick, address, city, region, country, 
                                        isp)
                            } else {
                                format!("\x0313{:-16} {:-15} {}, {} ({}) [{}]",
                                        nick, address, city, region, country, 
                                        isp)
                            }
                        };
                        if !account.is_empty() {
                            msg.push_str(&format!(" <<{}>>", account));
                        }
                    } else {
                        // No IP geolocation available.
                        msg = format!("\x0313{:-16} {}", nick, address);
                    }
                } else {
                    // No IP available.
                    msg = format!("\x0313{:-16} {}", nick, host);
                }
                tracker.write_ts_ctx(&msg, context);
            }
        }
    }
    
    fn create_database(path: &str) -> Result<(), TrackerError> {
        let conn = Connection::open(path)?;
        conn.execute(
            r" CREATE TABLE users (
                   nick, channel, host, account NOT NULL, address NOT NULL,
                   network, datetime_seen,
                   UNIQUE(nick, channel, host, account, address, network)
               ) ", NO_PARAMS)?;
            
        conn.execute(
            r" CREATE TABLE ip_addr_info (
                   ip, city, region, country, isp, lat, lon, date_added,
                   UNIQUE(ip)
               ) ", NO_PARAMS)?;
        Ok(())
    }
    
    pub (crate)
    fn update(&self,
              nick      : &str, 
              channel   : &str, 
              host      : &str, 
              account   : &str, 
              address   : &str, 
              network   : &str
             ) -> bool
    {
        match || -> SQLResult<bool> {
            let mut rec_added = false;
            let     conn      = Connection::open(&self.path)?;
            
            conn.busy_timeout(Duration::from_secs(DB_BUSY_TIMEOUT)).unwrap();
            
            let mut statement = conn.prepare(
                r" SELECT * FROM users
                   WHERE   nick    = ?
                     AND   channel = ?
                     AND   host    = ?
                     AND   account = ?
                     AND   address = ?
                     AND   network  LIKE ?
                   LIMIT 1
                ")?;
            let mut rows = statement.query(&[nick,    channel, host, 
                                             account, address, network])?;
            let found = {
                match rows.next() {
                    Ok(opt) => opt.is_some(),
                    Err(_) => false,
                }
             };
            if found {
                // Record exists, update it's datetime_seen field.
                conn.execute(
                    r" UPDATE  users 
                       SET     datetime_seen = datetime('now')
                       WHERE   nick    = ?
                         AND   channel = ?
                         AND   host    = ?
                         AND   account = ?
                         AND   address = ?
                         AND   network  LIKE ?
                    ", &[nick, channel, host, account, address, network])?;
            } else {
                // Record wasn'tthere to update; add a new one.
                conn.execute(
                    r" INSERT INTO users 
                       VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
                    ", &[nick, channel, host, account, address, network])?;
                    rec_added = true;
            }
            Ok(rec_added)
        }() {
            Ok(rec_added) => rec_added,
            Err(err) => {
                self.hc.threadsafe().print(&format!("ERROR: {}", err));
                false
            },
        }
    }
    pub (crate)
    fn update_ip_addr_info(&self,
                           ip       : &str,
                           city     : &str,
                           region   : &str,
                           country  : &str,
                           isp      : &str,
                           lat      : &str,
                           lon      : &str
                          ) -> bool
    {
        match || -> SQLResult<()> {
            let conn = Connection::open(&self.path)?;
            conn.busy_timeout(Duration::from_secs(DB_BUSY_TIMEOUT)).unwrap();

            conn.execute(
                r" INSERT INTO ip_addr_info
                   VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
                ", &[ip, city, region, country, isp, lat, lon])?;
            Ok(())
        }() {
            Ok(_)  => true,
            Err(_) => false,
        }
    }
    
    pub (crate)
    fn get_ip_addr_info(&self, 
                        ip: &str
                       ) -> Result<[String;8], TrackerError> 
    {
        let conn = Connection::open(&self.path)?;
        conn.busy_timeout(Duration::from_secs(DB_BUSY_TIMEOUT)).unwrap();
        
        // Record data: (ip, city, region, country, isp, lat, lon, link)
        let row: [String;8] = conn.query_row(
            r" SELECT * FROM ip_addr_info
               WHERE   ip = ?
               LIMIT 1
            ", &[ip], |row| Ok([row.get(0)?, row.get(1)?, row.get(2)?,
                                row.get(3)?, row.get(4)?, row.get(5)?,
                                row.get(6)?, row.get(7)?]))?;
        Ok(row)
    }
    
    fn get_db_entries(&self,
                      nick      : &str,
                      host      : &str,
                      account   : &str,
                      address   : &str,
                      network   : &str
                     ) -> Result<Vec<[String;5]>, TrackerError>
    {
        let conn = Connection::open(&self.path)?;
        conn.busy_timeout(Duration::from_secs(DB_BUSY_TIMEOUT)).unwrap();

        let nick_expr = {
            // Form the regular expression that'll be used to scan through
            // the database.
            if !nick.to_lowercase().contains("guest") {
                let mut nick_exp = self.trunc_expr.replace(nick, "")
                                                  .to_string();
                if nick_exp.len() < 4 {
                    nick_exp = nick[0..].to_string();
                } else {
                    nick_exp.push_str(r"[0-9_\-|]{0,3}$");
                }
                Regex::new(&nick_exp)?
            } else {
                Regex::new(nick)?
            }
        };
        // Register a custom matching function with SQLite3
        // to help find nicks that fuzzily match.
        conn.create_scalar_function(
            "NICKEXPR",
            1,
            FunctionFlags::SQLITE_UTF8  | FunctionFlags::SQLITE_DETERMINISTIC,
            move |ctx| {
                let text = ctx.get_raw(0).as_str().unwrap();
                Ok(nick_expr.is_match(text))
            })?;
        // Create a temporary table to facilitate the query.
        conn.execute(r"DROP TABLE IF EXISTS temp_table1", NO_PARAMS)?;
        conn.execute(
            r" CREATE TEMP TABLE temp_table1 AS
               SELECT  DISTINCT *
               FROM    users
               WHERE  (NICKEXPR(nick)
                   OR  host LIKE ?
                   OR  (account<>'' AND account LIKE ?)
                   OR  (address<>'' AND address=?))
               AND (network LIKE ? OR network LIKE 'elitebnc')
            ", &[host, account, address, network])?;
            
        // Query again using additional field values gathered from first 
        // query.
        let mut statement = conn.prepare(
            r" SELECT DISTINCT nick, channel, host, account, address
               FROM    users
               WHERE  (nick    IN  (SELECT DISTINCT nick FROM temp_table1)
                   OR  host    IN  (SELECT DISTINCT host FROM temp_table1)
                   OR  (account<>'' AND account
                               IN  (SELECT DISTINCT account 
                                                         FROM temp_table1))
                   OR  (address<>'' AND address 
                               IN  (SELECT DISTINCT address  
                                                         FROM temp_table1))
                                   )
               AND (network LIKE ? OR
                    network LIKE 'elitebnc')
               ORDER BY datetime_seen ASC
            ")?;
            
        conn.remove_function("NICKEXPR", 1)?;
            
        let rows = statement.query(&[network])?;
        
        let vrows: Vec<[String;5]> = rows.map(|r| Ok([r.get(0)?, r.get(1)?,
                                                      r.get(2)?, r.get(3)?, 
                                                      r.get(4)?]
                                                     )).collect()?;
        Ok(vrows)
    }
}


