# SSH-Honeypot
Simple SSH server to capture credentials

Useful for intercepting SSH credentials from vulnerability scanners.

**Prerequisites**<br />
```
apt-get install gcc
apt-get install cmake
apt-get install libssl-dev
apt-get install libssh-dev
```

Compile the following source code "ssh-faked.c" using `gcc -o ssh-faked ssh-faked.c -lssh`<br />
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libssh/libssh.h>
#include <libssh/server.h>

#define BUF1 100
#define BUF2 1000

void Usage();

int main(int argc, char **argv)
{
	ssh_bind sshbind;
	ssh_session session;
	int rv, csock;
	struct sockaddr_in peer;
	socklen_t peerlen;
	char cliip[BUF1] = {0}, user[BUF2] = {0}, pass[BUF2] = {0};
	ssh_message message;
	time_t tn;
	struct tm tmn;
	if(argc != 5)
	{
		Usage();
	return -1;
	}
	sshbind = ssh_bind_new();
	if(ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, argv[2]) != SSH_OK)
	{
		printf("Error: Unable to set bind port.\n");
		ssh_bind_free(sshbind);
		return -1;
	}
	if(ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, argv[1]) != SSH_OK)
	{
		printf("Error: Unable to set bind address.\n");
		ssh_bind_free(sshbind);
		return -1;
	}
	if(ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, argv[3]) != SSH_OK)
	{
		printf("Error: Unable to set DSA key.\n");
		ssh_bind_free(sshbind);
		return -1;
	}
	if(ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, argv[4]) != SSH_OK)
	{
		printf("Error: Unable to set RSA key.\n");
		ssh_bind_free(sshbind);
		return -1;
	}
	if(ssh_bind_listen(sshbind) < 0)
	{
		printf("Error: Unable to start listening socket.\n");
		ssh_bind_free(sshbind);
		return -1;
	}
	printf("Waiting for connection...\n");
	session = ssh_new();
	rv = ssh_bind_accept(sshbind, session);
	if(rv == SSH_ERROR)
	{
		printf("Error: Unable to accept incoming connection.\n");
		ssh_disconnect(session);
		ssh_free(session);
		ssh_bind_free(sshbind);
		return -1;
	}
	csock = ssh_get_fd(session);
	memset(&peer, 0, sizeof(peer));
	peer.sin_family = AF_INET;
	peerlen = sizeof(peer);
	getpeername(csock, (struct sockaddr *) &peer, &peerlen);
	strncpy(cliip, inet_ntoa(peer.sin_addr), BUF1-1);
	if(ssh_handle_key_exchange(session) != SSH_OK)
	{
		printf("Error: Unable to setup encryption.\n");
		ssh_disconnect(session);
		ssh_free(session);
		ssh_bind_free(sshbind);
		return -1;
	}
	while(1)
	{
		message = ssh_message_get(session);
		if(message == NULL)
		{
			printf("Error: Unable to handle messages.\n");
			ssh_disconnect(session);
			ssh_free(session);
			ssh_bind_free(sshbind);
			return -1;
		}
		if(ssh_message_type(message) == SSH_REQUEST_AUTH)
		{
			if(ssh_message_subtype(message) == SSH_AUTH_METHOD_PASSWORD)
			{
				strncpy(&user[0], ssh_message_auth_user(message), BUF2-1);
				strncpy(&pass[0], ssh_message_auth_password(message), BUF2-1);
				break;
			}
		}
		ssh_message_reply_default(message);
		ssh_message_free(message);
	}
	tn = time(NULL);
	tmn = *localtime(&tn);
	printf("Time: %d-%02d-%02d %02d:%02d:%02d\n", tmn.tm_year + 1900, tmn.tm_mon + 1, tmn.tm_mday, tmn.tm_hour, tmn.tm_min, tmn.tm_sec);
	printf("SSH Client IP = %s\n", cliip);
	printf("SSH Client Type = %s\n", ssh_get_clientbanner(session));
	printf("Username Supplied (inside brackets) = [%s]\n", user);
	printf("Password Supplied (inside brackets) = [%s]\n\n", pass);
	ssh_message_free(message);
	ssh_disconnect(session);
	ssh_free(session);
	ssh_bind_free(sshbind);
	return 0;
}

void Usage()
{
	printf("Usage:\n");
	printf("ssh-faked <bind IP> <bind port> <dsa keyfile> <rsa keyfile>\n\n");
	printf("<bind IP> is the IP address on this machine to listen on.\n");
	printf("<bind port> is the TCP port to listen on (usually 22).\n");
	printf("<dsa keyfile> The passwordless DSA keyfile to use.\n Generated using \"ssh-keygen -t dsa -b 1024\".\n");
	printf("<rsa keyfile> The passwordless RSA keyfile to use.\n Generated using \"ssh-keygen -t rsa -b 2048\".\n");
}
```

Create SSH keys.<br />
```
ssh-keygen -t rsa -b 2048 -f ./id_rsa
ssh-keygen -t dsa -b 1024 -f ./id_dsa
```

Run the SSH honeypot server (one shot).<br />
`./ssh-faked 10.192.103.22 22 ./id_dsa ./id_rsa`

Run the SSH honeypot server (continuous loop).<br />
`(while true; do ./ssh-faked 10.192.103.22 22 ./id_dsa ./id_rsa; done) | tee ~/ssh-faked.log`

