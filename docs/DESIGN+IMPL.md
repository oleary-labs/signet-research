Important characteristics of intended design:

* a single instance of a signet server - also referred to as a node - will be part of one or more groups of nodes.
* the overall protocol will define and manage groups of nodes. 
* groups are defined and managed users of the systems that can be application developers or any user who needs to manage keys and signing on behalf of end users.
* end users can submit key generation and signature requests to any node in a group.
  * the node that receives the requests will coordinate with other nodes in the group to accomplish the request.
* at any given time, a given node must be able to simultaneously and efficiently service multiple concurrent requests from users of the same and different groups.
  * in other words, the implementation must not have any bottlenecks handling keygen or signing within the same group of nodes or across different groups.  


* the implementation should strongly bias efficiency of the communication protocol
  * each round of the protocol keygen and signing protocols requires communication across the network.
  * the network should be assumed to be the internet - assume there will be significant latency
  * the implementation should require direct server-to-server connections for protocol communication. do not gossip protocol communications.
  * server-to-server communication requires that the implementation maintain direct connections to all active servers in all active groups.
  * these connections can and will be used to service many concurrent executions of keygen and signing protocols.


* currently, test logs show many instances of a 'round already finalized' message
  * this implies that the currently implementation is not efficiently detecting when a protocol round has finalized and is continuing to spam the network with unnecessary messages.


TODO
* implement the event-driven fix and remove the artificial sleep
* BUG: protocol hangs / spins if requested key does not exist


DATA MANAGEMENT
* the node config should have a parameter that refers to the data directory of the node.
  * the config parameter will be 'data_dir'
* all data artifacts will be stored under this directory.
  * necessary child file names in the data directory will be picked by the implementation
  * the current node key file will be named 'node.key'
  * we will use the bbolt library to store key shard data.
  * the key shards will be stored in a file named 'keyshards.db'