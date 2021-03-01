#![allow(unused_variables, dead_code, unused_imports)]

use regex::Regex;
use std::collections::HashSet;
use std::convert::From;
use std::error::Error;
use std::fmt;
use std::thread;

use hexchat_api::*;
use UserData::*;
use Priority::*;

use crate::nick_tracker::*;

// Register the entry points of the plugin.
//
dll_entry_points!(plugin_info, plugin_init, plugin_deinit);

/// Called when the plugin is loaded to register it with Hexchat.
///
fn plugin_info() -> PluginInfo {
    PluginInfo::new(
        "Nicktracker",
        "0.1.0",
        "Keeps track of user nicknames.")
}

fn plugin_init(hc: &'static Hexchat) -> i32 {
    hc.print("Nicktracker loaded");
    
    let udata = UserData::shared(NickTracker::new(hc));
    
    hc.hook_command("DBUPDATE", Norm, dbupdate,  DBUPDATE_HELP, udata.clone());
    hc.hook_command("DBWHO",    Norm, dbwho,     DBWHO_HELP,    udata.clone());
    hc.hook_command("IPLOOKUP", Norm, iplookup,  IPLOOKUP_HELP, udata.clone());
    hc.hook_command("DBTOGGLE", Norm, dbtoggle,  DBTOGGLE_HELP, udata.clone());
    
    hc.hook_print("Join",               Norm, user_join,        udata.clone());
    hc.hook_print("Quit",               Norm, user_quit,        udata.clone());
    hc.hook_print("Change Nick",        Norm, change_nick,      udata.clone());
    hc.hook_print("Your Nick Changing", Norm, your_nick_change, udata.clone());
    
    1
}

/// Called when the plugin is unloaded.
///
fn plugin_deinit(hc: &Hexchat) -> i32 {
    hc.print("Nicktracker unloaded");
    1
}

const DBTOGGLE_HELP : &str = "Toggles nick tracking on/off for the current \
                             channel.";
const IPLOOKUP_HELP : &str = "/IPLOOKUP <ip> Prints the geolocation for the \
                              IP.";
const DBWHO_HELP    : &str = "/DBWHO <user> Lists the nicknames for the given \
                              user.";
const DBUPDATE_HELP : &str = "/DBUPDATE Updates the nick database with user \
                              data for all users in the channel.";
                              
fn user_join(hc: &Hexchat, word: &[String], udata: &mut UserData) -> Eat
{
    udata.apply_mut(|nt: &mut NickTracker| { nt.on_user_join(word) })
}

fn user_quit(hc: &Hexchat, word: &[String], udata: &mut UserData) -> Eat
{
    udata.apply(|nt: &NickTracker| { nt.on_user_quit(word) })
}

fn change_nick(hc: &Hexchat, word: &[String], udata: &mut UserData) -> Eat
{
    Eat::None
}

fn your_nick_change(hc: &Hexchat, word: &[String], udata: &mut UserData) -> Eat
{
    Eat::None
}
                              
fn dbtoggle(hc       : &Hexchat,
            word     : &[String],
            word_eol : &[String],
            udata    : &mut UserData
           ) -> Eat
{
    udata.apply_mut(|nt: &mut NickTracker| { 
                        nt.on_cmd_dbtoggle(word, word_eol)
                    })
}

fn iplookup(hc       : &Hexchat,
            word     : &[String],
            word_eol : &[String],
            udata    : &mut UserData
           ) -> Eat
{
    Eat::None
}

fn dbupdate(hc       : &Hexchat,
            word     : &[String],
            word_eol : &[String],
            udata    : &mut UserData
           ) -> Eat
{
    Eat::None
}

fn dbwho(hc       : &Hexchat,
         word     : &[String],
         word_eol : &[String],
         udata    : &mut UserData
        ) -> Eat
{
    Eat::None
}

