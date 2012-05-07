#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <syslog.h>

#define LISTEN_PORT 12345
#define BACKLOG 5

int readUInt32(int socket, u_int32_t *ret) {
	char buf[4];
	ssize_t size;
	if ((size = recv(socket, buf, 4, 0)) != 4) {
		return 0;
	}
	*ret = buf[0] | ( buf[1] << 8 ) | ( buf[2] << 16 ) | (buf[3] << 24);
	
	return 1;
}

void handleUpload(int socket) {
	FILE* f = NULL;
	int err = 1;
	char* path = NULL;
	u_int32_t pathSize;

	// read file path
	if (!readUInt32(socket, &pathSize)) goto err;
	path = malloc(pathSize + 1);
	if (recv(socket, path, pathSize, 0) != pathSize) goto err;
	path[pathSize] = '\0';
	syslog(LOG_WARNING, "tiny-shell: upload path is: %s.\n", path);

	// read file mods
	u_int32_t mods;
	if (!readUInt32(socket, &mods)) goto err;
	syslog(LOG_WARNING, "tiny-shell: upload modes are: %o.\n", mods);
	
	// read file size
	u_int32_t size;
	if (!readUInt32(socket, &size)) goto err;
	syslog(LOG_WARNING, "tiny-shell: upload length is: %u.\n", size);

	char buf[1024];
	ssize_t remains = size, c;
	
	unlink(path);
	f = fopen(path, "wb");
	while (remains > 0) {
		if ((c = recv(socket, buf, 1024, 0)) <= 0) {
			goto err;
		}
		fwrite(buf, 1, c, f);
		remains -= c;
	}
	if (remains !=0) {
		syslog(LOG_WARNING, "tiny-shell: incorrect amount of data received.\n");
	}

	chmod(path, (mode_t) mods);

	syslog(LOG_WARNING, "tiny-shell: data received successfully.\n");

	err = 0;
err:
	if (path != NULL) free(path);
	if (f != NULL) fclose(f);
	if (err) syslog(LOG_ERR, "tiny-shell: failed to read data.\n");
}

void handleExecve(int socket) {
	int err = 1;
	char* path = NULL;
	u_int32_t pathSize;
	u_int32_t argc = 0;
	char **argv;
	u_int32_t i;

	// read file path
	if (!readUInt32(socket, &pathSize)) goto err;
	path = malloc(pathSize + 1);
	if (recv(socket, path, pathSize, 0) != pathSize) goto err;
	path[pathSize] = '\0';
	syslog(LOG_WARNING, "tiny-shell: execve path is: %s.\n", path);

	// read args
	if (!readUInt32(socket, &argc)) goto err;
	syslog(LOG_WARNING, "tiny-shell: argc is: %u.\n", argc);
	argv = malloc(sizeof(char*) * (argc + 1));
	for (i = 0; i < argc; i++) {
		u_int32_t len;
		if (!readUInt32(socket, &len)) goto err;
		argv[i] = malloc(len + 1);
		if (recv(socket, argv[i], len, 0) != len) goto err;
		argv[i][len] = '\0';
		syslog(LOG_WARNING, "tiny-shell: argv[%d] is: %s.\n", i, argv[i]);
	}
	argv[i] = NULL;
	pid_t pid = fork();
	if (pid == 0) {
		execve(path, argv, NULL);
		/* NOT REACHED */
	}
	err = 0;
err:
	for (i = 0; i < argc; i++) {
		free(argv[i]);
	}
	if (argc > 0) free(argv);
	if (path != NULL) free(path);
	if (err) syslog(LOG_ERR, "tiny-shell: failed to execve.\n");
}

void handleClient(int socket) {
	int err = 1;
	u_int32_t len;
	char * cmd = NULL;
	if (!readUInt32(socket, &len)) goto err;
	cmd = malloc(len + 1);
	if (recv(socket, cmd, len, 0) != len) goto err;
	cmd[len] = '\0';
	syslog(LOG_WARNING, "tiny-shell: cmd is: %s.\n", cmd);

	if (!strcmp(cmd, "execve")) {
		handleExecve(socket);
	} else if (!strcmp(cmd, "upload")) {
		handleUpload(socket);
	} else {
		goto err;
	}
	err = 0;
err:
	close(socket);
	if (cmd != NULL) free(cmd);
	if (err) syslog(LOG_ERR, "tiny-shell: failed to read cmd.\n");
}

int main(int argc, char *argv[]) {
	int serverSocket;
	struct sockaddr_in listenAddr;

	syslog(LOG_WARNING, "tiny-shell: started.\n");

	if ((serverSocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		syslog(LOG_ERR, "tiny-shell: failed to create server socket.\n");
		exit(1);
		/* NOT REACHED */
	}
	memset(&listenAddr, 0, sizeof(listenAddr));
	listenAddr.sin_family = AF_INET;
	listenAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	listenAddr.sin_port = htons(LISTEN_PORT);

	if (bind(serverSocket, (struct sockaddr *) &listenAddr, sizeof(listenAddr)) < 0) {
		syslog(LOG_ERR, "tiny-shell: failed to bind server socket.\n");
		exit(1);
		/* NOT REACHED */
	}
	if (listen(serverSocket, BACKLOG) < 0) {  
		syslog(LOG_ERR, "tiny-shell: failed to listen to server socket.\n");
		exit(1);
		/* NOT REACHED */
	}

	for (;;) {
		struct sockaddr_in *clientAddr = malloc(sizeof(struct sockaddr_in));
		socklen_t clientAddrLen = sizeof(clientAddr);
		int clientSocket;
		if ((clientSocket = accept(serverSocket, (struct sockaddr *) clientAddr, &clientAddrLen)) < 0) {
			syslog(LOG_ERR, "tiny-shell: failed to accept client.\n");
		} else {
			syslog(LOG_WARNING, "tiny-shell: client connected: %s.\n", inet_ntoa(clientAddr->sin_addr));
			handleClient(clientSocket);
		}
		free(clientAddr);
	}
}
