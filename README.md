
# Hexchat Nick Tracker

**PLEASE USE THIS TOOL WITH MATURITY AND DISCRETION**
*(be responsible - don't be a creeper)***.**

This tool is mainly intended for channel moderators.

This addon builds a database of metadata for each visitor to a channel. With 
this information, it can identify users despite them changing nicknames or
accounts (in many cases). This addon works best on IRC networks that, by 
default, include the users' IP's in their host info (e.g. *freenode*).

It takes a short span of time to build enough of a database for it to start
giving meaningful information. To start building this database for your
favorite channel, use the `/DBUPDATE` command to seed the database with the
current population, then turn on automatic tracking with `/DBTOGGLE` and let
it do its thing.

To make the output more readable, it's recommended to set Hexchat to a
monospace font like `DejaVu Sans Mono 10`. Switching to a monospace font will
visibly align the data if the Hexchat window is stretched wide enough so 
there isn't much text wrapping on the output.

The list of possible nicks (and user info) may contain false positives, but
generally they're very accurate. But if any items seem out of place, they 
probably are.

*Note: Mar 3, 21 - on this day or prior, the entries added to the DB may have
bad IP info. This can be fixed with this query and a commit - or just remove
the `~/.config/hexchat/addons/nicktracker-db.sqlite3` file and start over.*
```sql
DELETE
FROM ip_addr_info
WHERE city=""
```

This project is still under initial development, so there are still issues/bugs
to work out. However, it's functional enough at this point to be useful. But
expect a lot of fixes to be checked in with some frequency.

## Hexchat Commands
* `/DBUPDATE` 
    * Update the database with the users in the current channel.
* `/DBTOGGLE`
    * Turn on/off automatic tracking in the current channel.
* `/DBWHO <nick>`
    * Print information on the given nickname.
* `/IPLOOKUP <ip>` 
    * Try to get geolocation info for the given IP. It will generate a Google
      Maps link.

## Building
It's fairly easy to set up a Rust build environment on your system. You can find
instructions [here](https://www.rust-lang.org/learn/get-started). The process
is automated using `rustup`. Once that's in place, simply clone this project 
and launch the build process:
* For Linux, if the build fails, installing sqlite3 dev package should fix it.
* `git clone https://github.com/ttappr/hexchat_api.git`
* `git clone https://github.com/ttappr/nicktracker.git`
* `cd nicktracker`
* `cargo build --release`
* `cd target/release && ls -al` and there's your binary.

## Rust Hexchat API
This project uses a 
[Rust Hexchat API lib](https://github.com/ttappr/hexchat_api), 
which other developers may find useful for writing their own Rust Hexchat 
plugins. It has some nice features like
* A thread-safe API.
* Simple `user_data` objects.
* Abstractions like `Context` that make it simple to interact with specific 
  tabs/windows in the UI.
* Panic's are caught and displayed in the active window.


