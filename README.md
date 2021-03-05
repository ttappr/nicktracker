
# Hexchat Nick Tracker

**PLEASE USE THIS TOOL WITH MATURITY AND DISCRETION**
*(be responsible - don't be a creeper)***.**

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

This project is still under initial development, so there are still issues/bugs
to work out. However, it's functional enough at this point to be useful. But
expect a lot of fixes to be checked in with some frequency.

## Output

When a user enters a channel, if the tool has captured any previous information
on the nickname, the output could look something like below. 

The format is: `<nick> <ip/host> <geolocation-of-ISP-host> [<ISP-name>] <<<account-name>>>`

```
 USER JOINED: ArchieBunker
 ArchieBunker     123.123.123.123 New York, New York (United States) [Edith Communications] <<ArchieBunker>>
 HoneyBadger444   111.122.133.144 Bikini Bottom, Pacific Ocean (United States) [Squidward Ltd] <<ArchieBunker>>
 LaTeeDah         111.122.133.144 Bikini Bottom, Pacific Ocean (United States) [Squidward Ltd]
```

The geolocation data of the ISP is interesting because one can get a
general sense of the geographical distribution of the channel's population,
and one could learn something about geography if they were interested enough
in learning about their fellow users to use the `/IPLOOKUP` feature to see the
regions people come from on the map. The location is usually in the same
city/town as the user. Of course the geolocation won't be anywhere near users
if they're using a VPN, but in a lot of cases, they aren't.

On servers that mask out IP's by default - or the user has a cloak, the IP 
field will just contain their `host` string with no ISP geolocation info, 
followed by their `account`name if they are logged into a registered account.
If the `account` field is missing, they aren't logged in on a registered
account.

## Hexchat Commands
* `/DBUPDATE` 
    * Update the database with the users in the current channel.
* `/DBTOGGLE`
    * Turn on/off automatic tracking in the current channel.
* `/DBWHO <nick>`
    * Print information on the given nickname.
* `/IPLOOKUP <ip>` 
    * Try to get geolocation info for the given IP. It will generate a Google
      Maps link. The output is **much** more specific than what the 
      `USER JOINED` message shows (as above).
      
## Binaries
The first release with binaries can be found [here](https://github.com/ttappr/nicktracker/releases/tag/nicktracker-v0.1.0).

The binaries provided are:
* `libnicktracker.so`    (Linux)
* `nicktracker.dll`      (Windows)

To add it to Hexchat, you can put the relevant binary in the "addons" 
folder of your system's Hexchat config directory.
* `~/.config/hexchat/addons` for Linux
* `%APPDATA%\HexChat\addons` on Windows

Or they can be loaded manually from the menubar on the Hexchat UI:
* `Window > Plugins and Scripts > Load`

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

## The Creep Factor

One would hope that it wouldn't be necessary to explain this, but with the 
project publicly accessible, it's worth mentioning. The tool can in many
cases give geolocation data that is close enough to users to creep them out
if some discretion isn't used.

Many new users, and even old-timers, on IRC networks value their privacy and
expect some respect to be given that fact. If a user joins a channel and 
a regular, with the simple intention of being friendly, asks them right off the
bat how the weather is in Orlando Florida, that can sometimes evoke an extreme
reaction in people. In the worst case it can make them feel unsafe on
IRC and never come back.

I've found the best way to use the tool with discretion is simply **not to 
mention anything about it** to users who you aren't certain would be comfortable
with the fact that their IP's are visible to the world, and people really do take
note of it, and many bots and other entities are constantly logging such 
information.

Yes, users who would feel compromised if you mentioned their location without
any prior conversation on the topic are being somewhat naive. But they can learn
about IRC masking and privacy at their own pace without someone frightening them 
into doing it.






