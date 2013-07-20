#include "capwap.h"
#include "capwap_socket.h"

/* */
int capwap_socket_nonblocking(int sock, int nonblocking) {
	int flags;

	ASSERT(sock >= 0);

	/* Retrieve file descriptor flags */
	flags = fcntl(sock, F_GETFL, NULL);
	if (flags < 0) {
		return 0;
	}

	if (nonblocking) {
		flags |= O_NONBLOCK;
	} else {
		flags &= ~O_NONBLOCK;
	}

	if(fcntl(sock, F_SETFL, flags) < 0) {
		return 0;
	}

	return 1;
}

/* */
int capwap_socket_connect_timeout(int sock, struct sockaddr_storage* address, int timeout) {
	int result;
	struct pollfd fds;
	socklen_t size;

	ASSERT(sock >= 0);
	ASSERT(address != NULL);

	/* */
	result = connect(sock, (struct sockaddr*)address, sizeof(struct sockaddr_storage));
	if (result < 0) {
		if (errno == EINPROGRESS) {
			/* Wait to connection complete */
			for (;;) {
				memset(&fds, 0, sizeof(struct pollfd));
				fds.fd = sock;
				fds.events = POLLOUT;

				result = poll(&fds, 1, timeout);
				if ((result < 0) && (errno != EINTR)) {
					return 0;
				} else if (result > 0) {
					/* Check connection status */
					size = sizeof(int);
					if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (void*)&result, &size) < 0) {
						return 0;
					}

					if (result) {
						return 0;
					}

					/* Connection complete */
					break;
				}
			}
		} else {
			/* Unable to connect to remote host */
			return 0;
		}
	}

	return 1;
}

/* */
int capwap_socket_send_timeout(int sock, void* buffer, size_t length, int timeout) {
	int result;
	struct pollfd fds;
	size_t sendlength;

	ASSERT(sock >= 0);
	ASSERT(buffer != NULL);
	ASSERT(length > 0);

	sendlength = 0;
	while (sendlength < length) {
		memset(&fds, 0, sizeof(struct pollfd));
		fds.fd = sock;
		fds.events = POLLOUT;

		result = poll(&fds, 1, timeout);
		if ((result < 0) && (errno != EINTR)) {
			return -1;
		} else if (result > 0) {
			if (fds.revents == POLLOUT) {
				size_t leftlength = length - sendlength;

				result = send(sock, &((char*)buffer)[sendlength], leftlength, 0);
				if ((result < 0) && (errno != EINTR)) {
					return -1;
				} else if (result > 0) {
					sendlength += result;
				}
			} else {
				return -1;
			}
		}
	}

	return sendlength;
}

/* */
int capwap_socket_recv_timeout(int sock, void* buffer, size_t length, int timeout) {
	int result;
	struct pollfd fds;

	ASSERT(sock >= 0);
	ASSERT(buffer != NULL);
	ASSERT(length > 0);

	for (;;) {
		memset(&fds, 0, sizeof(struct pollfd));
		fds.fd = sock;
		fds.events = POLLIN;

		result = poll(&fds, 1, timeout);
		if ((result < 0) && (errno != EINTR)) {
			return -1;
		} else if (result > 0) {
			if (fds.revents == POLLIN) {
				result = recv(sock, buffer, length, 0);
				if ((result < 0) && (errno != EINTR)) {
					return -1;
				} else if (!result) {
					return 0;
				} else if (result > 0) {
					return result;
				}
			} else {
				return -1;
			}
		}
	}

	return -1;
}
