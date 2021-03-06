
//! This module contains the exported functions that Hexchat calls when the
//! addon is loaded and unloaded. It registers the commands the addon provides
//! and the Hexchat text event handlers.
//! 

use threadpool::ThreadPool;

use hexchat_api::*;
use Priority::*;

use crate::nick_tracker::*;

pub (crate) static mut THREAD_POOL: Option<ThreadPool> = None;

// Register the entry points of the plugin.
//
dll_entry_points!(plugin_info, plugin_init, plugin_deinit);

/// Called when the plugin is loaded to register it with Hexchat.
///
fn plugin_info() -> PluginInfo {
    PluginInfo::new(
        "Nicktracker",
        env!("CARGO_PKG_VERSION"),
        "Keeps track of user nicknames.")
}

/// The addon's DLL initialization function called by Hexchat when the addon
/// is loaded.
/// # Arguements
/// * `hc` - The Hexchat struct reference passed to the addon from Hexchat.
/// # Returns
/// * `1` indicating to Hexchat the addon was successfully loaded.
///
fn plugin_init(hc: &'static Hexchat) -> i32 {
    hc.print("Nicktracker loaded");
    
    unsafe {
        THREAD_POOL = Some(ThreadPool::new(1)); 
    }
    
    let udata = UserData::shared(NickTracker::new(hc));
    
    hc.hook_command("DBUPDATE", Norm, dbupdate,  DBUPDATE_HELP, udata.clone());
    hc.hook_command("DBWHO",    Norm, dbwho,     DBWHO_HELP,    udata.clone());
    hc.hook_command("IPLOOKUP", Norm, iplookup,  IPLOOKUP_HELP, udata.clone());
    hc.hook_command("DBTOGGLE", Norm, dbtoggle,  DBTOGGLE_HELP, udata.clone());
    
    hc.hook_print("Join",               Norm, user_join,        udata.clone());
    hc.hook_print("Quit",               Norm, user_quit,        udata.clone());
    hc.hook_print("Change Nick",        Norm, change_nick,      udata.clone());
    hc.hook_print("Your Nick Changing", Norm, change_nick,      udata);
    
    1
}

/// Called when the plugin is unloaded. This will remove the task thread by 
/// setting `THREAD_POOL` to `None`, then join existing threads before exiting.
/// It's possible that a couple tasks may slip in before it's set to `None`
/// but that should be fine.
/// # Arguments
/// * `hc` - The Hexchat reference.
/// # Returns
/// * `1`, indicating to Hexchat the addon was unloaded successfully.
///
fn plugin_deinit(hc: &Hexchat) -> i32 {
    hc.print("Nicktracker unloaded");
    unsafe { 
        if let Some(tp) = &THREAD_POOL {
            tp.join();
            THREAD_POOL = None;
        }
    }
    1
}

/// Called by the application to schedule tasks that happen on another thread
/// so the Hexchat GUI won't stagger or become laggy when operations like
/// web service requests take more time than usual. With a separate task thread
/// we should see no lags due to this addon's processing of user info.
///
pub (crate) fn thread_task<F>(job: F) 
where F: FnOnce() + Send + 'static
{
    unsafe {
        if let Some(tp) = &THREAD_POOL {
            tp.execute(job)
        }
    }
}

/// Reports how many tasks are in the threaded task handler queue.
/// # Returns
/// * The number of current tasks in the threaded task handler queue.
///
pub (crate) fn num_queued_tasks() -> usize {
    unsafe {
        if let Some(tp) = &THREAD_POOL {
            tp.queued_count()
        } else {
            999
        }
    }
}

const DBTOGGLE_HELP : &str = "/DBTOGGLE [ALL [ON|OFF]] \
                              Toggles nick tracking on/off for the current \
                              channel. If ALL is given alone, it toggles the \
                              state of each channel. If ON is given it \
                              activates all inactive channels - if OFF is \
                              given it deactivates all active channels.";
const IPLOOKUP_HELP : &str = "/IPLOOKUP <ip> Prints the geolocation for the \
                              IP.";
const DBWHO_HELP    : &str = "/DBWHO <user> Lists the nicknames for the given \
                              user.";
const DBUPDATE_HELP : &str = "/DBUPDATE Updates the nick database with user \
                              data for all users in the channel.";
        
/// Callback wrapper. Forwards the 'Join' text event to `NickTracker` for 
/// handling. 
///
fn user_join(_hc: &Hexchat, word: &[String], udata: &mut UserData) -> Eat
{
    udata.apply_mut(|nt: &mut NickTracker| { nt.on_user_join(word) })
}

/// Callback wrapper. Forwards 'Quit' text events on to `NickTracker` for
/// handling.
///
fn user_quit(_hc: &Hexchat, word: &[String], udata: &mut UserData) -> Eat
{
    udata.apply(|nt: &NickTracker| { nt.on_user_quit(word) })
}

/// Callback wrapper. Forwards 'Change Nick' text events on to `NickTracker` for
/// handling.
///
fn change_nick(_hc: &Hexchat, word: &[String], udata: &mut UserData) -> Eat
{
    udata.apply(|nt: &NickTracker| nt.on_user_change_nick(word))
}

/// Callback wrapper for the `/DBTOGGLE` command which it forwards to 
/// `NickTracker`. 
/// 
fn dbtoggle(_hc      : &Hexchat,
            word     : &[String],
            word_eol : &[String],
            udata    : &mut UserData
           ) -> Eat
{
    udata.apply_mut(|nt: &mut NickTracker| { 
                        nt.on_cmd_dbtoggle(word, word_eol)
                    })
}

/// Callback wrapper for the `/IPLOOKUP` command wich forwards to `NickTracker`
/// `on_cmd_ip_lookup()`.
///
fn iplookup(_hc      : &Hexchat,
            word     : &[String],
            word_eol : &[String],
            udata    : &mut UserData
           ) -> Eat
{
    udata.apply_mut(|nt: &mut NickTracker| { 
                        nt.on_cmd_ip_lookup(word, word_eol)
                    })
}

/// Callback wrapper for `/DBUPDATE` which fowards to `NickTracker`, 
/// `on_cmd_update()`.
///
fn dbupdate(_hc      : &Hexchat,
            word     : &[String],
            word_eol : &[String],
            udata    : &mut UserData
           ) -> Eat
{
    udata.apply_mut(|nt: &mut NickTracker| { 
                        nt.on_cmd_dbupdate(word, word_eol)
                    })
}

/// Command wrapper for `/DBWHO` which forwards to `NickTracker`, 
///`on_cmd_dbwho()`.
///
fn dbwho(_hc      : &Hexchat,
         word     : &[String],
         word_eol : &[String],
         udata    : &mut UserData
        ) -> Eat
{
    udata.apply_mut(|nt: &mut NickTracker| {
                        nt.on_cmd_dbwho(word, word_eol)
                    })
}

