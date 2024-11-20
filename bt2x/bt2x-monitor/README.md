# BT²X Monitor

This directory consists of a monitor application as well as a monitor library, which can be used to include a monitor in other applications.
The gossiping "primitives" are implemented in the `bt2x-common` library in the the `bt2x-common::gossip` module.

## HTTP Interface

The gossiping protocol uses a HTTP interface. There are two kinds of actions: **listen** (server) and **speak** (client).
Listening is the act of providing an endpoint (at `/listen`) where checkpoints can be sent to as part of the speak act.
Incoming gossip is verified against the most recent known checkpoint and verified using an inclusion proof provided by the log.
When successful, the request is then replied with the most freshest checkpoint.
In case of failure an error is returned.

## Verification

Two checkpoints are verified for consistency in the following way:

1. Verify that the incoming checkpoint was signed by the BT log Rekor.
2. Determine which checkpoint is the newest one
3. Request a consistency proof from the older tree size to the newer tree size.
4. Run a consistency proof with the proof hashes provided by the log.
5. Reply with a response indicating the result.

## Federation

The monitor can be federated with other instances of itself by adding the URL of the other monitor to the command.