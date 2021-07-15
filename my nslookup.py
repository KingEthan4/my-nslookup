from scapy.all import *

DNS_SERVER_ADDRESS =  "8.8.8.8"
DNS_SERVER_NAME = "Google DNS server"
DNS_PORT = 53
IP_ADDRESS_DELIMITER = '"'
BEFORE_LAST_INDEX = -2
NEXT_INDEX = 1
NON_AUTHORITATIVE_ANSWER = 0
NSLOOKUP_COMMAND = "nslookup"

def get_IP_of_domain(domain):
    """
    Function crates a dns query ans with the domain it got a parameter, and returns the response of the DNS server.
    :param domain: a domain.
    :type domain: str
    :return: the ip address which is extracted from the response of the dns serer.
    :rtype: str
    """

    response = "Server: " + DNS_SERVER_NAME + "\n" + "Address: " + DNS_SERVER_ADDRESS + "\n\n"
    # creating response which is like the response of cmd (showing the name and the address of the DNS server)

    fullmsg = Ether() / IP(dst = DNS_SERVER_ADDRESS) / UDP(dport = DNS_PORT) / DNS(qd = DNSQR(qname = domain))
    # creating the DNS query with the given domain

    ans = srp1(fullmsg, verbose=0)
    # receiving answer from DNS server

    # if searched domain wasn't found by the DNS server, the response of the server will be empty. So in the next few
    # lines I make sure to let the user know his domain was invalid.

    try: # trying to find the index where the ip address appears
        ip_address_index = (ans[DNS].summary()).index(IP_ADDRESS_DELIMITER)

    except ValueError: # value wasn't found- which means the response of the DNS server is empty.
        response += "can't find " + domain + ": Non-existent domain"
        return response

    if ans[DNS].aa == NON_AUTHORITATIVE_ANSWER: # checking if DNS response is authoritative or not.
        response += "Non-authoritative answer:\n"

    response += "Name:  " + domain + "\nAddress: " # making it look identical to cmd's nslookup

    response += ans[DNS].summary()[ip_address_index + NEXT_INDEX:BEFORE_LAST_INDEX]
    # returning ip address without these: ""

    return response


def main():
    print("Type 'nslookup' and then enter a domain. Like that: nslookup google.com")
    
    user_domain = input()
    if (user_domain[:len(NSLOOKUP_COMMAND)] != NSLOOKUP_COMMAND): # checking if user wrote nslookup at the start.
        print("Invalid command! Try writing " + NSLOOKUP_COMMAND + " at the start")
    else:
        user_domain = user_domain.replace(" ", "") # removing spaces, if user accidently wrote them.

        server_response = get_IP_of_domain(user_domain[len(NSLOOKUP_COMMAND):])

        print(server_response)


if __name__ == '__main__':
    main()
