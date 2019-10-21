#include <fstream>
#include <iostream>
#include <vector>
#include <unordered_set>

#define INBOUND 7  // length of "inbound"
#define OUTBOUND 8 // length of "outbound"
#define INBOUND_STRING "inbound"   // inbound direction string
#define OUTBOUND_STRING "outbound" // outbound direction string
#define INBOUND_INDEX 12  // start index of port number when direction is inbound
#define OUTBOUND_INDEX 13 // start index of port number when direction is inbound

using namespace std;

class Firewall {
private:
	/* sule_sets: rule numbers for different type of rule */
	/* [0]: inbound, tcp; [1]: inbound, udp; [2]: outbound, tcp; [3]: outbound, udp */
	vector<unordered_set<int>*> rule_sets;
	/* ports: {range_start, range_end} for each rule */
	vector<vector<unsigned short int>> ports;
	/* ip_addresses: {range_start, range_end} for each rule */
	vector<vector<unsigned int>> ip_addresses;

	/* Translate ip address from string to unsigned integer */ 
	unsigned int ipToInt(string ip_address);
	/* Split thr rule string into direction, protocol, port and ip_address */
	void splitRule(string& rule, string& direction, string& protocol, string& port, string& ip_address);
	/* Return the rule set index based on direction and protocol */
	int getRuleIndex(string& direction, string& protocol);
	/* Translate the port string into port range */
	void translate(string& port, unsigned short int& port_start, unsigned short int& port_end);
	/* Translate the ip_address string into ip range */
	void translate(string& ip_address, unsigned int& ip_start, unsigned int& ip_end);
	/* Parse the given string of rule, update data structures accordingly */
	void parseRule(string& s, int rule_num);
	/* Return whether the port is within the port range of specified rule number */
	bool portInRange(unsigned short int port, int rule_num);
	/* Return whether the ip is within the ip range of specified rule number */
	bool ipInRange(unsigned int ip, int rule_num);

public:
	/* Constructor */
	Firewall(string filename);
	/* Destructor */
	~Firewall();
	/* Return whether traffic with particular propoties is allowed */
	bool accept_packet(string direction, string protocol, int port, string ip_address);
};

/* Translate ip address from string to unsigned integer */ 
unsigned int Firewall::ipToInt(string ip_address){
	unsigned int result = 0;
	int index = 0;
	for(int i = 0; i < 4; i++){
		int next_index = ip_address.find(".", index);
		result = (result << 8) + stoi(ip_address.substr(index, next_index - index));
		index = next_index + 1;
	}
	return result;
}

/* Split thr rule string into direction, protocol, port and ip_address */
void Firewall::splitRule(string& s, string& direction, string& protocol, string& port, string& ip_address){
	int index;
	if(s[INBOUND] == ','){
		// inbound
		direction = INBOUND_STRING;
		protocol = s.substr(INBOUND + 1, 3);
		index = INBOUND_INDEX;
	}
	else{
		// outbound
		direction = OUTBOUND_STRING;
		protocol = s.substr(OUTBOUND + 1, 3);
		index = OUTBOUND_INDEX;
	}
	int comma_index = s.find(",", index);
	port = s.substr(index, comma_index - index);
	ip_address = s.substr(comma_index + 1, s.length() - comma_index - 1);
}

int Firewall::getRuleIndex(string& direction, string& protocol){
	int rule_set_index;
	if(direction.length() == INBOUND){
		if(protocol.compare("tcp") == 0) rule_set_index = 0;
		else rule_set_index = 1;
	}
	else{
		if(protocol.compare("tcp") == 0) rule_set_index = 2;
		else rule_set_index = 3;
	}

	return rule_set_index;
}

void Firewall::translate(string& port, unsigned short int& port_start, unsigned short int& port_end){
	int dash_index = port.find("-");
	if(dash_index < 0){
		port_start = (unsigned short int)stoi(port);
		port_end = port_start;
	}
	else{
		port_start = (unsigned short int)stoi(port.substr(0, dash_index));
		port_end = (unsigned short int)stoi(port.substr(dash_index + 1, port.length() - dash_index - 1));
	}
}

void Firewall::translate(string& ip_address, unsigned int& ip_start, unsigned int& ip_end){
	int dash_index = ip_address.find("-");
	if(dash_index < 0){
		ip_start = ipToInt(ip_address);
		ip_end = ip_start;
	}
	else{
		ip_start = ipToInt(ip_address.substr(0, dash_index));
		ip_end = ipToInt(ip_address.substr(dash_index + 1, ip_address.length() - dash_index - 1));
	}
}

void Firewall::parseRule(string& s, int rule_num){
	string direction, protocol, port, ip_address;
	splitRule(s, direction, protocol, port, ip_address);

	int rule_set_index = getRuleIndex(direction, protocol);
	unsigned short int port_start, port_end;
	translate(port, port_start, port_end);
	unsigned int ip_start, ip_end;
	translate(ip_address, ip_start, ip_end);
	// Insert rule number to according set
	rule_sets[rule_set_index]->insert(rule_num);
	// Push back port range
	if(port_start == port_end) ports.push_back(vector<unsigned short int> {port_start});
	else ports.push_back(vector<unsigned short int> {port_start, port_end});
	// Push back ip address range
	if(ip_start == ip_end) ip_addresses.push_back(vector<unsigned int> {ip_start});
	else ip_addresses.push_back(vector<unsigned int> {ip_start, ip_end});
}

bool Firewall::portInRange(unsigned short int port, int rule_num){
	if(ports[rule_num].size() == 1) return port == ports[rule_num][0];
	return port >= ports[rule_num][0] && port <= ports[rule_num][1];
}

bool Firewall::ipInRange(unsigned int ip, int rule_num){
	if(ip_addresses[rule_num].size() == 1) return ip == ip_addresses[rule_num][0];
	return ip >= ip_addresses[rule_num][0] && ip <= ip_addresses[rule_num][1];
}

/* Constructor */
Firewall::Firewall(string filename){
	for(int i = 0; i < 4; i++) rule_sets.push_back(new unordered_set<int>);

	// Open file in read mode
	ifstream infile(filename);
	if(!infile.is_open()){
		// If the file can't be opened
		cout << "Failure in Firewall constructor: Cannot open file." << endl;
	}

	// Parse the rules
	string line;
	int rule_num = 0;
	while(getline(infile, line)){
		parseRule(line, rule_num);
		rule_num++;
	}

}

/* Return whether traffic with particular propoties is allowed */
bool Firewall::accept_packet(string direction, string protocol, int port, string ip_address){
	// Get the set of rule numbers based on direction and protocol
	int rule_set_index = getRuleIndex(direction, protocol);
	unordered_set<int> set = *rule_sets[rule_set_index];
	// Search through rules to check 
	unsigned int ip = ipToInt(ip_address);
	for(auto it = set.begin(); it != set.end(); it++){
		int rule_num = *it;
		if(portInRange((unsigned short int)port, rule_num) 
			&& ipInRange(ip, rule_num)) return true;
	}
	return false;
}

/* Destructor */
Firewall::~Firewall(){
	for(int i = 0; i < rule_sets.size(); i++)
		delete rule_sets[i];
}