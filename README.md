
# Hexchat Nick Tracker

**PLEASE USE THIS TOOL WITH MATURITY AND DISCRETION**
*(don't be a creeper)***.**

This addon builds a database of metadata for each visitor to a channel. With 
this information, it can identify users despite them changing nicknames or
accounts (in many cases). This addon works best on IRC networks that don't
mask out the users' IP information in their user information.

It takes a short span of time to build enough of a database for it to start
giving meaningful information. To start building this database for your
favorite channel, use the `/DBUPDATE` command to seed the database with the
current population, then turn on automatic tracking with `/DBTOGGLE` and let
it do its thing.

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


