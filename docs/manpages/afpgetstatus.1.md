# NAME

afpgetstatus - Get simple status information from an AFP server without
logging into it

# SYNOPSIS

**afpgetstatus \[afp_url|ipaddress\[:port\]\]**

# DESCRIPTION

**afpgetstatus** is a command-line tool that parses and prints the status
information of an AFP server. It does this without having to login to a
server.

It is a response to the DSI GetStatus request (which is the same as the
AFP FPGetSrvrInfo).

It handles IPv4 and IPv6 addresses. When using ports with an IPv6
address, the IP address must be enclosed in square brackets,
and the entire URL including port must be enclosed in double quotes.

# OPTIONS

**afp_url** an AFP url in the form of *afp://servername:port/*. Any
other AFP url fields (username, volume name, etc) are ignored.

**ipaddress** the IP address of the server

**port** the TCP port to connect to (optional)

# SEE ALSO

afpcmd(1)
