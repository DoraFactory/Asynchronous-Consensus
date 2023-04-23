# HBBFT
This is a streamlined version of HoneyBadger BFT library

## Algorithms
- Honey Badger: Each node inputs transactions. The protocol outputs a sequence of batches of transactions.

- Dynamic Honey Badger: A modified Honey Badger where nodes can dynamically add and remove other nodes to/from the network.

- Queueing Honey Badger: Works exactly like Dynamic Honey Badger, but includes a built in transaction queue.

- Subset: Each node inputs data. The nodes agree on a subset of suggested data.

- Broadcast: A proposer node inputs data and every node receives this output.

- Binary Agreement: Each node inputs a binary value. The nodes agree on a value that was input by at least one correct node.

- Threshold Sign: Each node inputs the same data to be signed, and outputs the unique valid signature matching the public master key. It is used as a pseudorandom value in the Binary Agreement protocol.

- Threshold Decryption: Each node inputs the same ciphertext, encrypted to the public master key, and outputs the decrypted data.

- Synchronous Key Generation A dealerless algorithm that generates keys for threshold encryption and signing. Unlike the other algorithms, this one is completely synchronous and should run on top of Honey Badger (or another consensus algorithm)

- External crates developed for this library
    - Threshold Crypto: A threshold cryptosystem for collaborative message decryption and signature creation.

We have simplified algorithm naming conventions from the original paper.

|  Algorithm Name  | Original Name                                 |
| ---------------- | --------------------------------------------- |
| Honey Badger     | HoneyBadgerBFT                                |
| Subset           | Asynchronous Common Subset (ACS)              |
| Broadcast        | Reliable Broadcast (RBC)                      |
| Binary Agreement | Asynchronous Binary Byzantine Agreement (ABA) |
