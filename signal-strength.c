#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

void usage() {
	printf("syntax: signal-strength <interface> <mac>\n");
	printf("sample: signal-strength wlan0 11:22:33:44:55:66\n");
}

typedef struct {
	char* dev_;
	char* bs_;
} Param;

Param param = {
	.dev_ = NULL,
	.bs_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	param->bs_ = argv[2];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}


	while (true) {
		struct pcap_pkthdr* header;
		const u_char* signal;
		const u_char* packet;
        	const u_char *bssid;
		u_char bs[7];
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
        	unsigned int rl = *(packet+2) + *(packet+3)*0xff;
        	bssid = packet+40;
		signal = packet+18;
		int temp;
		int flag=0;

		for(int i=0; i<6; ++i)
		{
			param.bs_[3*i+2] = '\0';
			sscanf(&param.bs_[3*i], "%x", &temp);
			bs[i] = (u_char)temp;
		}
		bs[6] = '\0';
		if(bs[0] == bssid[0] && bs[1] == bssid[1] && bs[2] == bssid[2] && bs[3] == bssid[3] && bs[4] == bssid[4] && bs[5] == bssid[5]) 
		{
			printf("%02X:%02X:%02X:%02X:%02X:%02X\n", bs[0], bs[1], bs[2], bs[3], bs[4], bs[5]);
			printf("-%ddBm\n", 0x100-signal[0]);
		}

	}

	pcap_close(pcap);
}
