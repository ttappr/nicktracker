
//! This module provides the user data related functionality and abstracts the
//! database operations for `NickTracker`. It also handles the printing of the
//! lists of matching nicknames.
//! 

use fallible_iterator::FallibleIterator;
use regex::Regex;
use rusqlite::Connection;
use rusqlite::functions::Context as SQLContext;
use rusqlite::functions::FunctionFlags;
use rusqlite::NO_PARAMS;
use rusqlite::Result as SQLResult;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use hexchat_api::*;

use crate::nick_tracker::*;
use crate::tracker_error::*;

/// How long a thread will wait for the DB to become available if it's locked.
///
const DB_BUSY_TIMEOUT: u64 = 5; // Seconds.

/// Maximum number of rows of data to print when listing possible matches for
/// a given user.
///
const MAX_ROWS_PRINT : usize = 15;

// Used to truncate nicks with numbers at the end.
const TRUNC_EXPR : &str = r"[0-9_\-|]{0,3}$";

// Used to detect generic Guest login nicks.
const GUEST_EXPR : &str = r"^(?:[Gg]uest_?\d*|[Kk]iwi_?\d*)$";

// Used to grab the obfuscated IP from host strings.
const OBFIP_EXPR : &str = r"irc-(?:[\w]+\.){3,4}IP$";

// The type for the map that caches `Regex`s used in queries.
//
type RegexMap = HashMap<String, Arc<Regex>>;

/// The `NickData` object interacts with the nickname/user info database.
/// It handles the queries and other operations.
///
#[derive(Clone)]
pub (crate)
struct NickData {
    hc         : &'static Hexchat,
    path       : String,
    trunc_expr : Regex,
    guest_expr : Regex,
    obfip_expr : Regex,
    expr_cache : Arc<Mutex<RegexMap>>,
}

impl NickData {
    /// Creates a new `NickData` object. If the database doesn't exist it tries
    /// to creat it - if unsuccessful, it will panic, but that shouldn't
    /// happen.
    ///
    pub (crate)
    fn new(hc: &'static Hexchat) -> Self {
        if let Some(path) = Self::check_database(hc) {
            let nd = NickData { 
                hc,
                path, 
                trunc_expr : Regex::new(TRUNC_EXPR).unwrap(),
                guest_expr : Regex::new(GUEST_EXPR).unwrap(),
                obfip_expr : Regex::new(OBFIP_EXPR).unwrap(),
                expr_cache : Arc::new(Mutex::new(HashMap::new())),
            };
            nd.update_user_table().expect("Unable to update database.");
            nd
        } else {
            panic!("Unable to create new database for Nick Tracker.");
        }
    }

    /// Escapes the underscores and percent characters in strings to be passed
    /// to the SQL `LIKE` operation. In SQL `%` and `_` are wildcards in the 
    /// `LIKE` operation.
    ///
    fn sql_escape(s: &str) -> String {
        let mut es = String::new();
        for ch in s.chars() {
            match ch {
                '_'  => es.push_str(r"\_"),
                '%'  => es.push_str(r"\%"),
                '\\' => es.push_str(r"\\"),
                _    => es.push(ch),
            }
        }
        es
    }

    /// Prints the DB records related to the user info given in the paramters.
    /// # Arguments
    /// * `nick`    - The nickname to print the related records of.
    /// * `host`    - The host the user is logged in from.
    /// * `account` - The user's account, if available. Empty str if not.
    /// * `address` - The network address of the user.
    /// * `network` - The Hexchat network of the channel the user is in.
    /// * `tracker` - The `NickTracker` object.
    /// * `context` - The context that is bound to the chat the user is in.
    ///
    #[allow(clippy::too_many_arguments)]
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
        //const IPV6_LEN: usize = 39;
        
        if let Ok(db_entries) = self.get_db_entries(nick, host, account, 
                                                    address, network)
        {
            for [nick, host, account, address] in &db_entries {
                let mut msg;
                if !address.is_empty() {
                    if let Ok(addr_info) = tracker.get_ip_addr_info(address) {
                        let [ip,  city, region, country,
                             isp, _lat, _lon,   _link    ] = addr_info;
                        msg = {
                            if ip.len() > IPV4_LEN {
                                format!("\x0309\x02{:-16}\x0F \
                                         \x0311{:-39} {}, {} ({}) [{}]",
                                        nick, address, city, region, country, 
                                        isp)
                            } else {
                                format!("\x0309\x02{:-16}\x0F \
                                         \x0311{:-15} {}, {} ({}) [{}]",
                                        nick, address, city, region, country, 
                                        isp)
                            }
                        };
                    } else {
                        // No IP geolocation available.
                        msg = format!("\x0309\x02{:-16}\x0F \x0311{}", 
                                      nick, address);
                    }
                } else {
                    // No IP available.
                    msg = format!("\x0309\x02{:-16}\x0F \x0311{}", nick, host);
                }
                if !account.is_empty() {
                    msg.push_str(
                        &format!(" <<\x0313\x02{}\x0f\x0311>>", account));
                }
                tracker.write_ts_ctx(&msg, context);
            }
        }
    }
    
    /// Creates a new database with the required tables. One table for user
    /// info; and another for the resolved geolocation data for IP's. 
    ///
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
    
    /// This is used internally the SQL regular expression custom functions.
    /// # Arguments
    /// * `ctx`         - The SQL context which provides the paramters to the 
    ///                   function.
    /// * `expr_cache`  - The map that holds the previously compiled regular
    ///                   expressions.
    /// # Returns
    /// * The resulting (sub)string that was found in the SQL function 
    ///   invocation parameter for the target string.
    ///
    fn regex_internal(ctx        : &SQLContext,
                      expr_cache : &Arc<Mutex<RegexMap>>
                     ) -> SQLResult<String> 
    {
        use rusqlite::Error as SQLError;

        let expr_cache = &mut *expr_cache.lock().unwrap();
        let expr_text  = ctx.get_raw(0).as_str()
                                       .map_err(|e| 
                                            SQLError::UserFunctionError(
                                                e.into()))?;
        let targ_text  = ctx.get_raw(1).as_str()
                                       .map_err(|e| 
                                            SQLError::UserFunctionError(
                                                e.into()))?;
        
        let expr = match expr_cache.get(expr_text) {
            Some(expr) => expr.clone(),
            None => {
                expr_cache.insert(
                    expr_text.to_string(),
                    Arc::new(Regex::new(expr_text)
                             .map_err(|e| 
                                  SQLError::UserFunctionError(
                                        e.into()))?));
                expr_cache.get(expr_text).unwrap().clone()
            }
        }; 
        Ok(expr.find(targ_text).map_or("", |m| m.as_str()).to_string())    
    }

    /// Adds a `REGEX_FIND` function to the SQL database, for use in queries.
    /// Expressions are cached, and SQLite also uses a form of LRU cache so
    /// the function doesn't need to be reexecuted if given params SQLite 
    /// has already seen passed to it. This find function will return the 
    /// match result as a string (`Regex.find()` is applied).
    ///
    fn add_regex_find_function(&self,
                               conn : &Connection
                              ) -> Result<(), TrackerError> 
    {
        let expr_cache = self.expr_cache.clone();
        conn.create_scalar_function(
            "REGEX_FIND",
            2,
            FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
            move |ctx| {
                NickData::regex_internal(ctx, &expr_cache)
            })?;
        Ok(())
    }
    
    /// Adds a `REGEX_MATCH` function to the SQL database, for use in queries.
    /// Expressions are cached, and SQLite also uses a form of LRU cache so
    /// the function doesn't need to be reexecuted if given params SQLite 
    /// has already seen passed to it. This match function will return a 
    /// boolean to SQLite if the expression as param 1 matches the data as
    /// param 2.
    ///
    fn add_regex_match_function(&self,
                                conn : &Connection,
                               ) -> Result<(), TrackerError> 
    {
        let expr_cache = self.expr_cache.clone();
        conn.create_scalar_function(
            "REGEX_MATCH",
            2,
            FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
            move |ctx| {
                NickData::regex_internal(ctx, &expr_cache)
                          .map(|s| !s.is_empty())
            })?;
        Ok(())
    }
    
    /// Adds the user's information to the database if it isn't already there.
    /// # Arguments
    /// * `nick`    - The user's nickname.
    /// * `channel` - The channel name associated with the chat the user is in.
    /// * `host`    - The host data of the user.
    /// * `account` - The account name of the user if there is one.
    /// * `address` - The IP address of the user, if it can be extracted.
    /// * `network` - The IRC server network name.
    /// # Returns
    /// * `true` if the database was modified, `false` if not.
    ///
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
            let     obfip     = self.obfip_expr.find(host)
                                    .map_or("", |m| m.as_str()).to_string();
            let network_esc = NickData::sql_escape(network);
            
            conn.busy_timeout(Duration::from_secs(DB_BUSY_TIMEOUT)).unwrap();
            
            let mut statement = conn.prepare(
                r" SELECT * FROM users
                   WHERE   nick    = ?
                     AND   channel = ?
                     AND   host    = ?
                     AND   account = ?
                     AND   address = ?
                     AND   network  LIKE ? ESCAPE '\'
                   LIMIT 1
                ")?;
            let mut rows = statement.query(&[nick,    channel, host, 
                                             account, address, &network_esc])?;
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
                         AND   network  LIKE ? ESCAPE '\'
                    ", &[nick, channel, host, account, address, &network_esc])?;
            } else {
                // Record wasn'tthere to update; add a new one.
                conn.execute(
                    r" INSERT INTO users 
                       VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?)
                    ", &[nick,    channel, host, 
                         account, address, network, &obfip])?;
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
    
    /// Adds IP address and geolocation data to the database so it can be
    /// queried from there instead of from the web service.
    /// # Arguments
    /// * `ip`        - The IP to store.
    /// * `city`      - The city the host of the IP is located in.
    /// * `region`    - The region of the IP host.
    /// * `country`   - The country it resides in.
    /// * `isp`       - The ISP that owns the IP.
    /// * `lat`       - The latitude of the host on the map.
    /// * `lon`       - The longitide of the host.
    /// # Returns
    /// * `true` if the database was modified, `false` if not.
    ////
    #[allow(clippy::too_many_arguments)]
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
        || -> SQLResult<()> {
            let conn = Connection::open(&self.path)?;
            conn.busy_timeout(Duration::from_secs(DB_BUSY_TIMEOUT)).unwrap();

            conn.execute(
                r" INSERT INTO ip_addr_info
                   VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
                ", &[ip, city, region, country, isp, lat, lon])?;
            Ok(())
        }().is_ok()
    }
    
    /// Retrieves IP information from the database if it has it.
    /// # Arguments
    /// * `ip`  - The IP to get geolocation data for.
    /// # Returns
    /// * `Ok([String:8])` is returned if the DB has the data; `Err(err)` if 
    ///   not, or there was a problem getting the data.
    ///
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
    
    /// Gets DB entries for the intended user. These entries can be related
    /// to each other by similarities in their records. The logic is a bit
    /// fuzzy on how the query works.
    ///
    /// * `nick`    - The nickname of the user.
    /// * `host`    - The host of the user.
    /// * `account` - The user's account name.
    /// * `address` - The users IP address.
    /// * `network` - The IRC network the user is logged in to.
    /// # Returns
    /// * `Ok(Vec<[String:5]>)` holding "matching" records for the user. These
    ///   may identify other accounts they use, places near where they lived
    ///   etc. `Err(err)` is returned if there was a problem finding records.
    ///
    fn get_db_entries(&self,
                      nick      : &str,
                      host      : &str,
                      account   : &str,
                      address   : &str,
                      network   : &str
                     ) -> Result<Vec<[String;4]>, TrackerError>
    {
        use regex::escape;
        
        let conn = Connection::open(&self.path)?;
        conn.busy_timeout(Duration::from_secs(DB_BUSY_TIMEOUT)).unwrap();

        let nick_expr = {
            // Form the regular expression that'll be used to scan through
            // the database.
            if !self.guest_expr.is_match(nick) {
                let mut nick_expr  = String::new();
                let     nick_trunc = self.trunc_expr.replace(nick, "")
                                                    .to_string();
                if nick_trunc.len() < 4 {
                    nick_expr.push_str("^_*");
                    if nick.len() > 4 {
                        nick_expr.push_str(&escape(&nick[0..4]));
                    } else {
                        nick_expr.push_str(&escape(nick));
                    }
                    nick_expr.push_str(r"[0-9_\-|]{0,6}$");
                } else {
                    nick_expr.push_str("^_*");
                    nick_expr.push_str(&escape(&nick_trunc));
                    nick_expr.push_str(r"[0-9_\-|]{0,3}$");
                }
                nick_expr
            } else {
                // There should be no matches for this. We don't want to match
                // based on temporary user names.
                "^#$".to_string()
            }
        };

        let network_esc = NickData::sql_escape(network);
        let account_esc = NickData::sql_escape(account);
        let host_esc    = NickData::sql_escape(host);

        // Add regular expression functions to the SQLite database.
        self.add_regex_find_function(&conn)?;
        self.add_regex_match_function(&conn)?;

        let obfuscated_ip = self.obfip_expr.find(host)
                                           .map_or("", |m| m.as_str())
                                           .to_string();

        // Create a temporary table to facilitate the query.
        conn.execute(r"DROP TABLE IF EXISTS temp_table1", NO_PARAMS)?;
        conn.execute(
            r" CREATE TEMP TABLE temp_table1 AS
               SELECT  DISTINCT *
               FROM    users
               WHERE  (REGEX_MATCH(?, nick)
                   OR  host LIKE ? ESCAPE '\'
                   OR  (obfuscated_ip<>'' AND obfuscated_ip=?)
                   OR  (account<>'' AND account LIKE ? ESCAPE '\')
                   OR  (address<>'' AND address=?))
               AND network LIKE ? ESCAPE '\'
            ", &[&nick_expr, 
                 &host_esc, 
                 &obfuscated_ip,
                 &account_esc, 
                 address, 
                 &network_esc])?;
            
        // Query again using additional field values gathered from first 
        // query.
        let mut statement = conn.prepare(
            r" SELECT DISTINCT nick, host, account, address
               FROM    users
               WHERE  ((NOT REGEX_MATCH(?, nick))
                       AND nick IN  (SELECT DISTINCT nick FROM temp_table1)
                   OR  host     IN  (SELECT DISTINCT host FROM temp_table1)
                   OR  (account<>'' AND account
                                IN  (SELECT DISTINCT account
                                                          FROM temp_table1))
                   OR (address<>'' AND address
                                IN  (SELECT DISTINCT address
                                                          FROM temp_table1))
                   OR (obfuscated_ip<>'' AND obfuscated_ip
                                IN  (SELECT DISTINCT obfuscated_ip
                                                          FROM temp_table1))
                      )
               AND network LIKE ? ESCAPE '\'
               ORDER BY datetime_seen DESC
            ")?;
        
        let rows = statement.query(&[GUEST_EXPR, &network_esc])?;
        
        let vrows: Vec<[String;4]> = rows.map(|r| Ok([r.get(0)?, r.get(1)?,
                                                      r.get(2)?, r.get(3)?]
                                                     )).take(MAX_ROWS_PRINT)
                                                       .collect()?;
        Ok(vrows)
    }
    
    /// This checks for the existence of the database, and creates it if it
    /// doesn't exist. It will try and determine where the `addons` folder is
    /// on the user's system in an OS agnostic way.
    /// # Arguments
    /// * `hc` - The Hexchat reference.
    /// # Returns
    /// * The path to the sqlite3 user information database in the config
    ///   folder of the user.
    ///
    fn check_database(hc: &Hexchat) -> Option<String> {
        let addons_path = Path::new(&hc.get_info("xchatdir")
                                       .expect("Unable to locate Hexchat's \
                                                addons directory."))
                               .join("addons")
                               .into_boxed_path();
                                       
        let db_path = addons_path.join("nicktracker-db.sqlite3")
                                 .into_boxed_path();
        
        let addons_path_string = addons_path.to_str()
                                            .expect("Unable to generate \
                                                     addons path string.")
                                            .to_string();
                                            
        let db_path_string = db_path.to_str()
                                    .expect("Unable to generate the \
                                             database path string.")
                                    .to_string();
        
        if !addons_path.exists() {
            if let Err(err) = std::fs::create_dir(addons_path) {
                // Unable to create addons folder for Hexchat.
                hc.print(
                    &format!("⚠️\t\x0313Unable to create addons folder \
                             for Hexchat ({}): {}", addons_path_string, err)
                );
                return None;
            }
        }
        if !db_path.exists() {
            if let Err(err) = Self::create_database(&db_path_string) 
            {
                // Unable to create database.
                hc.print(
                    &format!("⚠️\t\x0313Unable to create the database \
                              for Nick Tracker ({}): {}", db_path_string, err)
                );
                return None
            }
        }
        Some(db_path_string)
    }
    
    /// Any late modifications to the database are contained in this function.
    /// This function ensures that the tables and data in the database are kept
    /// current so users don't have to delete their current database and start
    /// a new one if the schema changes at all.
    ///
    fn update_user_table(&self) -> Result<(), TrackerError>
    {
        let conn = Connection::open(&self.path)?;
 
        self.add_regex_find_function(&conn)?;
        self.add_regex_match_function(&conn)?;

        // Extract the column names of the 'users' table. 
        let mut stmt = conn.prepare(r"PRAGMA table_info(users)")?;
        let     rows = stmt.query(NO_PARAMS)?;
        let     cols = rows.map(|r| Ok(r.get(1)?)).collect::<Vec<String>>()?;
        
        if !cols.contains(&"obfuscated_ip".to_string()) {
            self.hc.print("Updating user table of database.");
            
            // 'obfuscated_ip' not found in table, update table.
            conn.execute(
                    r" ALTER TABLE users ADD COLUMN obfuscated_ip
                     ", NO_PARAMS)?;
            conn.execute(
                    r" UPDATE users
                       SET obfuscated_ip=REGEX_FIND(?, host)
                       WHERE REGEX_MATCH(?, host)
                     ", &[OBFIP_EXPR, OBFIP_EXPR])?;
        }
        Ok(())
    }
}



