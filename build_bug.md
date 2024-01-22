## 2024.01.22:
### Problem 1:
```
the trait bound `tokio::net::TcpStream: AsFd` is not satisfied
the trait `AsFd` is not implemented for `tokio::net::TcpStream`
could not compile `hyper` (lib) due to previous error.
```
Fix 1:
Change `hyper` version to `0.14.26` by:
cargo update -p hyper@0.14.28 --precise 0.14.26

--Note 0.14.28 is the current version of hyper, change it to your current version before using this command.