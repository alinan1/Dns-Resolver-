import socket
import struct
import random
import json

# Example query spec as JSON
dns_query_spec = {
    "id": random.randint(0, 65535),
    "qr": 0,      # query
    "opcode": 0,  # standard query
    "rd": 0,      # no recursion because --> iterative resolver
    "questions": [
        {
            "qname": "ilab1.cs.rutgers.edu",
            "qtype": 1,   # A record
            "qclass": 1   # IN
        }
    ]
}


def build_query(query_spec):
    # Header fields
    ID = query_spec["id"]
    QR = query_spec["qr"] << 15
    OPCODE = query_spec["opcode"] << 11
    AA, TC = 0, 0
    RD = query_spec["rd"] << 8
    RA, Z, RCODE = 0, 0, 0
    flags = QR | OPCODE | AA | TC | RD | RA | Z | RCODE

    QDCOUNT = len(query_spec["questions"])
    ANCOUNT, NSCOUNT, ARCOUNT = 0, 0, 0

    header = struct.pack("!HHHHHH", ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)

    # Question section
    question_bytes = b""
    for q in query_spec["questions"]:
        labels = q["qname"].split(".")
        for label in labels:
            question_bytes += struct.pack("B", len(label)) + label.encode()
        question_bytes += b"\x00"  # end of qname
        question_bytes += struct.pack("!HH", q["qtype"], q["qclass"])

    return header + question_bytes


def parse_name(data, offset):
    labels = []
    jumped = False
    original_offset = offset

    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        # pointer
        if (length & 0xC0) == 0xC0:
            if not jumped:
                original_offset = offset + 2
            pointer = struct.unpack("!H", data[offset:offset+2])[0]
            offset = pointer & 0x3FFF
            jumped = True
            continue
        labels.append(data[offset+1:offset+1+length].decode())
        offset += length + 1

    if not jumped:
        return ".".join(labels), offset
    else:
        return ".".join(labels), original_offset

#your parse_rr from part2
def parse_rr(data, offset):
  record={}
  ## your code from part 2
  name, offset = parse_name(data, offset)
  (rtype, rclass, ttl, rdlength) = struct.unpack("!HHIH", data[offset:offset+10])
  record["name"]=name
  record["type"]=rtype
  record["class"]=rclass
  record["ttl"]=ttl
  record["rdlength"]=rdlength
  offset += 10
  
  # parse rdata based on the type(AAAA, A, NS, CNAME)
  if rtype == 1: # A record
        record["rdata"] = socket.inet_ntoa(data[offset:offset+rdlength])
        offset += rdlength 
  elif rtype == 28: # AAAA record
        record["rdata"] = socket.inet_ntop(socket.AF_INET6, data[offset:offset+rdlength])
        offset += rdlength
  elif rtype == 2: # NS record
        nsname, _ = parse_name(data, offset)
        record["rdata"] = nsname
        offset += rdlength
  elif rtype == 5: # CNAME record
        cname, _ = parse_name(data, offset)
        record["rdata"] = cname
        offset += rdlength
  else:
        record["rdata"] = data[offset:offset+rdlength]
        offset += rdlength
  
  return record, offset

def parse_response(data):
    response = {}
    (ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT) = struct.unpack("!HHHHHH", data[:12])

    response["id"] = ID
    response["qr"] = (flags >> 15) & 1
    response["opcode"] = (flags >> 11) & 0xF
    response["aa"] = (flags >> 10) & 1
    response["tc"] = (flags >> 9) & 1
    response["rd"] = (flags >> 8) & 1
    response["ra"] = (flags >> 7) & 1
    response["rcode"] = flags & 0xF
    response["qdcount"] = QDCOUNT
    response["ancount"] = ANCOUNT
    response["nscount"] = NSCOUNT
    response["arcount"] = ARCOUNT

    offset = 12
    # Skip questions
    for _ in range(QDCOUNT):
        while data[offset] != 0:
            offset += data[offset] + 1
        offset += 1
        offset += 4  # qtype + qclass

    # Parse Answer RRs
    answers = []
    for _ in range(ANCOUNT):
        rr, offset = parse_rr(data, offset)
        answers.append(rr)

    authorities=[]
    # Parse Authority RRs (NS)
    #Add code to parse NS records
    for _ in range(NSCOUNT):
        rr, offset = parse_rr(data, offset)
        authorities.append(rr)
    
    additionals=[]
    # Parse Additional RRs (A, AAAA, etc.)
    #Add code to Parse additonal records
    for _ in range(ARCOUNT):
        rr, offset = parse_rr(data, offset)
        additionals.append(rr) 
        
    
    response["answers"] = answers
    response["authorities"] = authorities
    response["additionals"] = additionals

    return response



def dns_query(query_spec, server=("1.1.1.1", 53)): #server=("1.1.1.1", 53)
    query = build_query(query_spec)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(query, server)
    data, _ = sock.recvfrom(512)
    sock.close()
    return parse_response(data)


def iterative_resolve(query_spec):
    ROOT_SERVERS = [
        "198.41.0.4",   # a.root-servers.net
        "199.9.14.201", # b.root-servers.net
        "192.33.4.12",  # c.root-servers.net
    ]

    # Queue of servers: begin at the roots
    servers = ROOT_SERVERS[:]
    print("root servers:", servers)

    #To keep track
    #path_ip = []

    while servers:
        # 1. Take the next server and query it 
        server_ip = servers.pop(0) # set serverip equal to firt root server in list
        #path_ip.append(server_ip)

        # Send the DNS query to this server 
        response = dns_query(query_spec, (server_ip, 53))

        # 2. Check answer section for A records, if present return IP and done
        a_answers = [rr for rr in response.get("answers", []) if rr.get("type") == 1] # if in answers rr type is A(1)
        if a_answers:
            return {"answers": response["answers"], } # ("path": path_ip)# return answers if A record found

        # 3. If No A answer -> follow referral using NS (Authority) plus glue (Additional)
        # Get the NS hostnames from the Authority section
        nsNames = [rr["rdata"] for rr in response.get("authorities", []) if rr.get("type") == 2]  

        # Find a glue A/AAAA in Additional whose owner name matches one of those NS hostnames
        newServer = None
        for ns in nsNames: #in list of ns names
            for add in response.get("additionals", []): #in additionals section
                if add.get("name") == ns and add.get("type") in (1, 28): # if name matches ns and type is A or AAAA
                    newServer = add["rdata"]  # take rdata of that additional record (IP STRING)
                    break # stop scanning additionals after finding first glue
            if newServer: 
                break #stop scanning ns names after finding first glue

        # If no glue is present, stop with an error (per assignment constraint)
        if not newServer:
            return {"error": "No glue found"} #(path_ip": path_ip)

        # 5. Continue the loop with the new server IP
        servers = [newServer]


if __name__ == "__main__":
    response = iterative_resolve(dns_query_spec)
    
    print(json.dumps(response,indent=2))