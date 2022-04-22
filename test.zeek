#
global ip_map: table[addr] of string;
global agent_counts: table[addr] of count;

event connection_state_remove(c: connection)
    {
    local ua: string;
    # print(c);
	if(c?$http)
		{
		# print fmt("http.");
		if(c$http?$user_agent)
			{
			ua =to_lower(c$http$user_agent);
			print fmt("%s is user agent", c$http$user_agent);
			if(c$id$orig_h !in agent_counts)
				{
				ua =to_lower(c$http$user_agent);
				ip_map[c$id$orig_h] = ua;
				agent_counts[c$id$orig_h] = 0;
    			++agent_counts[c$id$orig_h];
				}
    		else if(ua !in ip_map[c$id$orig_h])
    			{
    			ip_map[c$id$orig_h] = ip_map[c$id$orig_h] + ua;
    			print(ip_map[c$id$orig_h]);
    			++agent_counts[c$id$orig_h];
    			if(agent_counts[c$id$orig_h] >= 3) print fmt("%s is Proxy.", c$id$orig_h);
    			}
    		}
    	}
    # print(ip_map);
    # print(agent_counts);
    }
