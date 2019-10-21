# Firewall
This is a Firewall class written in C++.

### Parameters
When designing the firewall class, my first idea is to use a data structure as binary search tree to store the rules, which would provide better time complexity for the `accept_packet` method (explained in the optimization section below). However, because of the time limit of coding, I decided to use more simple data structures:

* `rule_sets`: a vector of 4 pointers, each pointer pointing to an unordered_set (hash table) of rule numbers with particular property:
    * `*rule_sets[0]`: containing rule numbers with **inbound** direction and **tcp** protocol
    * `*rule_sets[1]`: containing rule numbers with **inbound** direction and **udp** protocol
    * `*rule_sets[2]`: containing rule numbers with **outbound** direction and **tcp** protocol
    * `*rule_sets[3]`: containing rule numbers with **outbound** direction and **udp** protocol
* `ports`: a vector of port ranges and port numbers, sorted by rule number.
    * If the port parameter of the i_th rule is a range: port[i] = {port_start, port_end}
    * If the port parameter of the i_th rule is a number: port[i] = {port_number}
* `ip_addresses`: a vector of ip ranges and ip numbers, sorted by rule number.
    * If the ip parameter of the i_th rule is a range: ip_addresses[i] = {ip_start, ip_end}
    * If the ip parameter of the i_th rule is a number: ip_addresses[i] = {ip_number}

#### Integer types
In order to reduce space that is consumed to store the rules:
* `unsigned short int` for port numbers since the range for port numbers is [1, 65535].
* `unsigned int` for ip adresses, since the range is [0.0.0.0, 255.255.255.255].

### Methods
#### Public Methods
* `::Firewall`: Read the rules from a cvs file specified by argument, construct the firewall by initializing the data structures based on the rules.
* `::~Firewall()`: Destruct and free the allocated pointers.
* `::accept_packet`: Check whether a traffic with particular properties is allowed. Workflow for this method is:
    * Get the corresponding rule_sets index based on the direction and protocol properties.
    * Get the set of rule number based on the rule_sets index.
    * For each rule number in the set, check whether both the port number and ip address are within the range. If they are, return true.
    * After iterating through all rules within the set, if no matching is found, return false.

#### Private Methods
* `::ipToInt`: Translate ip address from string to unsigned integer.
* `::splitRule`: Split thr rule string into direction, protocol, port and ip_address.
* `::getRuleIndex`: Return the rule set index based on direction and protocol.
* `::translate`: Translate the port string or ip address string into port range (overriding using different argument type).
* `::parseRule`: Parse the given string of rule, update data structures accordingly.
* `::portInRange`: Return whether the port is within the port range of specified rule number.
* `::ipInRange`: Return whether the ip is within the ip range of specified rule number.

### Test
I didn't have time to write a test script to generate a large data file and test my implementation at scale or write a specific test file to test each function. But during my coding, I tried to test each method function by running several tiny test cases, trying to include as much corner cases as possible. If I can have more time, I will firstly write test program to make sure that each method is performing correctly, and then write a scipt to generate random large data file and test the whole inplementation.

### Optimization
One possible optimization would be using binary search tree to store the rules. For example, we can consrtuct two BST, one for port numbers and one for ip adresses. For each port range or ip address range, we store the rule numbers that including this range. Therefore, the node for each tree would be like
```class treeNode {
public:
	int range_start;
	int range_end;
	unordered_set<int>* rule_set;
};
```

Then we can construct a BST class derived from the set containor with customed comparator:

```class myComparator {
public:
    bool operator() (const treeNode& node1, const treeNode& node2) const {
        return node1.range_start < node2.range_start;
    }
};

class BST : public set <treeNode, myComparator> {

};
```

Then, when the `::accept_packet` is called, we first search the BST to find the rule numbers for both the port number and the ip address, then check the direction and protocol properties. Since the BST is sorted by the port/ip address, it will take O(logn) time for searching.

However, with this data structure, the construction of the Firewall would be much more complex. Whenever we read in a new rule, we need to search the two binary search trees. If the range is not overlapping with the ranges already in the tree, we can directly add a new node. However, if it is, then we will need to split the range into different parts accordingly.

### Interested Team
I'm particularly interested in the platform team. Since I'm looking for a full-time job as a back-end software engineer and my interested topics are distributed systems, cloud computing and storage systems, I think the work of the platform team attracts me most.