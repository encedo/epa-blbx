#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/spi/spidev.h>
#include <sys/stat.h>
#include <signal.h>
#include <termios.h>

#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <linux/limits.h>

static void pabort(const char *s);
static void parse_opts(int argc, char *argv[]);
static void print_usage(const char *prog);
static void sig_handler(int signo);

static void hex_dump(const void *src, size_t length, size_t line_size, char *prefix);

static int spi_init(void);
static int spi_transfer(int fd, uint8_t const *tx, uint8_t const *rx, size_t len);

static int encedo_get_readvnm(void);
static int encedo_get_deviceid(void);
static int encedo_get_deviceinfo(void);
static int encedo_get_powerstatus(void);
static int encedo_get_suervisormode(void);
static int encedo_get_activemcu(void);
static int encedo_get_activeusbports(void);
static int encedo_get_event(void);
static int encedo_get_rgb(void);
static int encedo_get_lowbat(void);
static int encedo_get_criticallowbat(void);
static int encedo_get_accelsensitivity(void);
static int encedo_get_pcbtemp(void);

static int encedo_set_writenvm(void);
static int encedo_set_setmagic(void);
static int encedo_set_unlockadminmode(void);
static int encedo_set_lowbat(void);
static int encedo_set_criticallowbat(void);
static int encedo_set_accelsensitivity(void);
static int encedo_set_supervisormode(void);
static int encedo_set_enableusbport(void);
static int encedo_set_disableusbport(void);
static int encedo_set_enablemcu(void);
static int encedo_set_disablemcu(void);
static int encedo_set_erasemcu(void);
static int encedo_set_rgb(void);
static int encedo_set_poweroff(void);

int bootloader_send_hex(int fd_cdc, int fd_hexfile);
int bootloader_preview(int fd);

static int debug = 0;
static int verbose = 0;
static char device[64] = {"/dev/spidev0.1"};
static int fd;

static char blfile[PATH_MAX], blport[PATH_MAX]; 

static char oper[32];
static char oper_arg[32];

int main(int argc, char *argv[]) {
	int ret = 0;

	setbuf(stdout, NULL);	//do not buffer 'stdout'

	memset(blport, 0, sizeof(blport));
	memset(blfile, 0, sizeof(blfile));

	parse_opts(argc, argv);
	
	signal(SIGUSR1, sig_handler);	//user define
	signal(SIGKILL, sig_handler);	//kill command (
	signal(SIGSTOP, sig_handler);	//stop (ctrl+z)
        signal(SIGINT,  sig_handler);	//     (ctrl+c)
        signal(SIGQUIT, sig_handler);    //     (ctrl+c)
	
	if (strlen(blport) > 0) {
    		int fd, fd2, ret;

    		fd = open(blport, O_RDWR | O_NOCTTY | O_SYNC);
   	 	if (fd < 0) {
        		printf("Error opening %s: %s\n", blport, strerror(errno));
        		exit(EXIT_FAILURE);
    		}
		
		fd2 = open(blfile, O_RDONLY | O_NONBLOCK );
    		if (fd2 < 0) {
           		printf("Port preview mode\n");
			bootloader_preview(fd);
			close(fd);
           		exit(EXIT_FAILURE);
    		}

    		ret = bootloader_send_hex(fd, fd2);
    		printf("Finished with code: %d\n", ret);

    		close(fd);
    		close(fd2);
        	exit(EXIT_SUCCESS);
	}

	spi_init();
	if (strlen(oper) == 0) {
		encedo_get_powerstatus();
	} else 
        if (strcmp("GET_ReadNVM", oper) == 0){
                encedo_get_readvnm();
		printf("Error: TBD\n");
        } else
        if (strcmp("GET_DeviceID", oper) == 0){
                encedo_get_deviceid();
        } else
        if (strcmp("GET_DeviceInfo", oper) == 0){
                encedo_get_deviceinfo();
        } else
        if (strcmp("GET_PowerStatus", oper) == 0){
                encedo_get_powerstatus();
        } else
        if (strcmp("GET_SupervisorMode", oper) == 0){
                encedo_get_suervisormode();
        } else
        if (strcmp("GET_ActiveMCU", oper) == 0){
                encedo_get_activemcu();
        } else
        if (strcmp("GET_ActiveUSBPorts", oper) == 0){
  	       	encedo_get_activeusbports();
        } else
        if (strcmp("GET_Event", oper) == 0){
                encedo_get_event();
        } else
        if (strcmp("GET_RGB", oper) == 0){
                encedo_get_rgb();
        } else
        if (strcmp("GET_LowBat", oper) == 0){
                encedo_get_lowbat();
        } else
        if (strcmp("GET_CriticalLowBat", oper) == 0){
                encedo_get_criticallowbat();
        } else
        if (strcmp("GET_AccelSensitivity", oper) == 0){
                encedo_get_accelsensitivity();
        } else
        if (strcmp("GET_BoardTemperature", oper) == 0){
                encedo_get_pcbtemp();
        } else


        if (strcmp("SET_WriteNVM", oper) == 0){
                encedo_set_writenvm();
		printf("Error: TBD\n");
        } else
        if (strcmp("SET_SetMagic", oper) == 0){
                encedo_set_setmagic();		
        } else
        if (strcmp("SET_UnlockAdminMode", oper) == 0){
                encedo_set_unlockadminmode();
        } else
        if (strcmp("SET_LowBat", oper) == 0){
	        encedo_set_lowbat();	
        } else
        if (strcmp("SET_CriticalLowBat", oper) == 0){
                encedo_set_criticallowbat();
        } else
        if (strcmp("SET_AccelSensitivity", oper) == 0){
                encedo_set_accelsensitivity();
        } else
        if (strcmp("SET_SupervisorMode", oper) == 0){
 	        encedo_set_supervisormode();
        } else
        if (strcmp("SET_EnableUSBPort", oper) == 0){
                encedo_set_enableusbport();
		printf("Error: TBD\n");
        } else
        if (strcmp("SET_DisableUSBPort", oper) == 0){
                encedo_set_disableusbport();
		printf("Error: TBD\n");
        } else
        if (strcmp("SET_EnableMCU", oper) == 0){
                encedo_set_enablemcu();
        } else
        if (strcmp("SET_DisableMCU", oper) == 0){
                encedo_set_disablemcu();
        } else
        if (strcmp("SET_EraseMCU", oper) == 0){
                encedo_set_erasemcu();
        } else
        if (strcmp("SET_PowerOFF", oper) == 0){
                encedo_set_poweroff();
        } else
	 if (strcmp("SET_RGB", oper) == 0){
                encedo_set_rgb();
        } else {
		printf("Error: Operation unknown\n");
        }

	close(fd);
	exit(EXIT_SUCCESS);
	//return ret;
}

static void sig_handler(int signo) {
    int ret;

    if (signo == SIGUSR1) {
        printf("received SIGUSR1\n");
    }
    else if (signo == SIGKILL) {
        printf("received SIGKILL\n");
    }
    else if (signo == SIGSTOP) {
        printf("received SIGSTOP\n");
    }
    else if (signo == SIGINT) {
        printf("received SIGINT\n");
    }

    sleep(1);

    if (fd) {
        close(fd);
       	fd = 0;
    }

    fprintf(stdout, "\nByebye\n");
    exit(0);
}

static int encedo_get_readvnm(void) {
}

static int encedo_get_deviceid(void) {
        int ret = 0;
        uint8_t tx[32];
        uint8_t rx[32];
        int size;

        if (fd < 0) {
                return -1;
        }

        memset(tx, 0xFF, sizeof(tx));
        memset(rx, 0xFF, sizeof(rx));
        tx[0] = 0x21;
        size = 18;
        ret = spi_transfer(fd, tx, rx, size);
        if (ret < 1) {
                pabort("can't send spi message");
        }
        if (debug) {
                hex_dump(tx, size, 16, "TX");
                hex_dump(rx, size, 16, "RX");
        }

        if (verbose) printf("Device ID:\n");
	for (size=0; size<16; size++) {
		printf("%02x", (unsigned char)rx[2+size]);
	}
	printf("\n\n");
        return ret;
}

static int encedo_get_deviceinfo(void) {
        int ret = 0;
        uint8_t tx[96];
        uint8_t rx[96];
        int size;

        if (fd < 0) {
                return -1;
        }

        memset(tx, 0xFF, sizeof(tx));
        memset(rx, 0xFF, sizeof(rx));
        tx[0] = 0x22;
        size = 66;
        ret = spi_transfer(fd, tx, rx, size);
        if (ret < 1) {
                pabort("can't send spi message");
        }
        if (debug) {
                hex_dump(tx, size, 16, "TX");
                hex_dump(rx, size, 16, "RX");
        }

	if (verbose) printf("Device info:\n");
	printf("%s\n\n", rx+2);	
        return ret;
}

static int encedo_get_powerstatus(void) { 
        int ret = 0;
        uint8_t tx[16];
        uint8_t rx[16];
        int size;
	#define SPICMD_STATUS_BYTE_EXTVCC	0x08
	#define SPICMD_STATUS_BYTE_PG		0x04
	#define SPICMD_STATUS_BYTE_CHARGING	0x02
	#define SPICMD_STATUS_BYTE_MOTION	0x01

        if (fd < 0) {
                return -1;
        }

        memset(tx, 0xFF, sizeof(tx));
        memset(rx, 0xFF, sizeof(rx));
        tx[0] = 0x23;
        size = 6;

        ret = spi_transfer(fd, tx, rx, size);
        if (ret < 1) {
                pabort("can't send spi message");
        }
        if (debug) {
                hex_dump(tx, size, 16, "TX");
                hex_dump(rx, size, 16, "RX");
        }

	if (verbose) printf("Power status:\n");
	if (rx[1] & SPICMD_STATUS_BYTE_MOTION) printf("motion ");
	if (rx[1] & SPICMD_STATUS_BYTE_CHARGING) printf("charging ");
	if (rx[1] & SPICMD_STATUS_BYTE_PG) printf("pg ");
	if (rx[1] & SPICMD_STATUS_BYTE_EXTVCC) printf("line ");
        size = (unsigned int)rx[2] + 256*(unsigned int)rx[3];
	printf("%dmV %d%%\n\n", size, (unsigned char)rx[4]);

        return ret;
}

static int encedo_get_suervisormode(void) {
        int ret = 0;
        uint8_t tx[16];
        uint8_t rx[16];
        int size;

        if (fd < 0) {
                return -1;
        }

        memset(tx, 0xFF, sizeof(tx));
        memset(rx, 0xFF, sizeof(rx));
        tx[0] = 0x24;
        size = 4;
        ret = spi_transfer(fd, tx, rx, size);
        if (ret < 1) {
                pabort("can't send spi message");
        }
        if (debug) {
                hex_dump(tx, size, 16, "TX");
                hex_dump(rx, size, 16, "RX");
        }

        if (verbose) printf("Supervisor mode:\n");
        printf("%02x\n\n", (unsigned char)rx[2]);
        return ret;
}

static int encedo_get_activemcu(void) {
        int ret = 0;
        uint8_t tx[16];
        uint8_t rx[16];
        int size;

        if (fd < 0) {
                return -1;
        }

        memset(tx, 0xFF, sizeof(tx));
        memset(rx, 0xFF, sizeof(rx));
        tx[0] = 0x25;
        size = 4;
        ret = spi_transfer(fd, tx, rx, size);
        if (ret < 1) {
                pabort("can't send spi message");
        }
        if (debug) {
                hex_dump(tx, size, 16, "TX");
                hex_dump(rx, size, 16, "RX");
        }

        if (verbose) printf("Active MCU:\n");
	printf("[");
        size = (unsigned int)rx[2] + 256*(unsigned int)rx[3];
        if (size & 0x001) printf("1 ");
        if (size & 0x002) printf("2 ");
        if (size & 0x004) printf("3 ");
        if (size & 0x008) printf("4 ");
        if (size & 0x010) printf("5 ");
        if (size & 0x020) printf("6 ");
        if (size & 0x040) printf("7 ");
        if (size & 0x080) printf("8 ");
        if (size & 0x100) printf("9 ");
        if (size & 0x200) printf("10 ");
        printf("]\n\n");
        return ret;
}

static int encedo_get_activeusbports(void) {
	int ret = 0;
        uint8_t tx[16];
        uint8_t rx[16];
        int size;

        if (fd < 0) {
                return -1;
        }

        memset(tx, 0xFF, sizeof(tx));
        memset(rx, 0xFF, sizeof(rx));
        tx[0] = 0x26;
        size = 4;
        ret = spi_transfer(fd, tx, rx, size);
        if (ret < 1) {
                pabort("can't send spi message");
        }
        if (debug) {
                hex_dump(tx, size, 16, "TX");
                hex_dump(rx, size, 16, "RX");
        }

        if (verbose) printf("Active USB port:\n");
	printf("[");
        size = (unsigned int)rx[2] + 256*(unsigned int)rx[3];
        if (size & 0x001) printf("1 ");
        if (size & 0x002) printf("2 ");
        if (size & 0x004) printf("3 ");
        if (size & 0x008) printf("4 ");
        if (size & 0x010) printf("5 ");
        if (size & 0x020) printf("6 ");
	if (size & 0x040) printf("7 ");
        if (size & 0x080) printf("8 ");
        if (size & 0x100) printf("9 ");
        if (size & 0x200) printf("10 ");
        printf("]\n\n");
        return ret;
}

const char *events_tab[64] = {"NONE", "MAINPOWERLOST", "BATLOW", "BATCRITICALLOW", "MOTIONDETECTED", "FORCESHUTDOWN", "EMERGENCYERASE", "MAINPOWERBACK", 
                              "BATCHARGED", "MOTIONSTOPED", "ADMINUNLOCKED", "BATCHARGING", "BATLOWOFF", "BATCRITICALLOWOFF", "free1", "RESET", 
		   /* 0x10 */ "LOW_POWER_RESET", "WINDOW_WATCHDOG_RESET", "INDEPENDENT_WATCHDOG_RESET", "SOFTWARE_RESET", "POWER-ON_RESET (POR) / POWER-DOWN_RESET (PDR)", "EXTERNAL_RESET_PIN_RESET", "OPTION_BYTES_RESET (OBL)","UNKNOWN_RESET",
                   /* 0x18 */ "ERASED_C1","ERASED_C2","ERASED_C3","ERASED_C4","ERASED_C5","ERASED_C6","ERASED_C7","ERASED_C8","ERASED_C9","ERASED_C10","x22","x23","x24","x25","x26","x27",
		   /* 0x28 */ "0x28"};
static int encedo_get_event(void) {
        int ret = 0;
        uint8_t tx[32];
        uint8_t rx[32];
        int size;

        if (fd < 0) {
                return -1;
        }

        memset(tx, 0xFF, sizeof(tx));
        memset(rx, 0xFF, sizeof(rx));
        tx[0] = 0x27;
        size = 20;
        ret = spi_transfer(fd, tx, rx, size);
        if (ret < 1) {
                pabort("can't send spi message");
        }
        if (debug) {
                hex_dump(tx, size, 16, "TX");
                hex_dump(rx, size, 16, "RX");
        }

        if (verbose) printf("Event:\n");
        int cnt = (unsigned char)rx[2];	//set max count
        printf("%02x ", cnt);
	if (verbose) {
                for(size=0; size<cnt; size++) {
			unsigned char event = (unsigned char)rx[size+3];			
                        printf("%s ", events_tab[event]);
                }
	} else {
		for(size=0; size<cnt; size++) {
        		printf("%02x", (unsigned char)rx[size+3]);
		}
	}
        printf("\n\n");
        return ret;
}

static int encedo_get_rgb(void) {
        int ret = 0;
        uint8_t tx[16];
        uint8_t rx[16];
        int size;

        if (fd < 0) {
                return -1;
        }

        memset(tx, 0xFF, sizeof(tx));
        memset(rx, 0xFF, sizeof(rx));
        tx[0] = 0x28;
        size = 6;
        ret = spi_transfer(fd, tx, rx, size);
        if (ret < 1) {
                pabort("can't send spi message");
        }
        if (debug) {
                hex_dump(tx, size, 16, "TX");
                hex_dump(rx, size, 16, "RX");
        }

        if (verbose) printf("RGB:\n");
        printf("#%02x%02x%02x\n\n", (unsigned char)rx[2],(unsigned char)rx[3],(unsigned char)rx[4]);
        return ret;
}

static int encedo_get_lowbat(void) {
        int ret = 0;
        uint8_t tx[96];
        uint8_t rx[96];
        int size;

        if (fd < 0) {
                return -1;
        }

        memset(tx, 0xFF, sizeof(tx));
        memset(rx, 0xFF, sizeof(rx));
        tx[0] = 0x29;
        size = 4;
        ret = spi_transfer(fd, tx, rx, size);
        if (ret < 1) {
                pabort("can't send spi message");
        }
        if (debug) {
                hex_dump(tx, size, 16, "TX");
                hex_dump(rx, size, 16, "RX");
        }

        if (verbose) printf("Threshold - low bat:\n");
        printf("%u\n\n", rx[2]);
        return ret;
}

static int encedo_get_criticallowbat(void) {
        int ret = 0;
        uint8_t tx[96];
        uint8_t rx[96];
        int size;

        if (fd < 0) {
                return -1;
        }

        memset(tx, 0xFF, sizeof(tx));
        memset(rx, 0xFF, sizeof(rx));
        tx[0] = 0x2a;
        size = 4;
        ret = spi_transfer(fd, tx, rx, size);
        if (ret < 1) {
                pabort("can't send spi message");
        }
        if (debug) {
                hex_dump(tx, size, 16, "TX");
                hex_dump(rx, size, 16, "RX");
        }

        if (verbose) printf("Threshold - critial low bat:\n");
        printf("%u\n\n", rx[2]);
        return ret;
}

static int encedo_get_pcbtemp(void) {
        int ret = 0;
        uint8_t tx[96];
        uint8_t rx[96];
        int size;

        if (fd < 0) {
                return -1;
        }

        memset(tx, 0xFF, sizeof(tx));
        memset(rx, 0xFF, sizeof(rx));
        tx[0] = 0x2c;
        size = 6;
        ret = spi_transfer(fd, tx, rx, size);
        if (ret < 1) {
                pabort("can't send spi message");
        }
        if (debug) {
                hex_dump(tx, size, 16, "TX");
                hex_dump(rx, size, 16, "RX");
        }

        if (verbose) printf("Board temperature:\n");
        size = (unsigned int)rx[2] + 256*(unsigned int)rx[3];
        printf("%d.%d`C\n\n", size/10, size%10);
        return ret;

}

static int encedo_get_accelsensitivity(void) {
        int ret = 0;
        uint8_t tx[96];
        uint8_t rx[96];
        int size;

        if (fd < 0) {
                return -1;
        }

        memset(tx, 0xFF, sizeof(tx));
        memset(rx, 0xFF, sizeof(rx));
        tx[0] = 0x2b;
        size = 4;
        ret = spi_transfer(fd, tx, rx, size);
        if (ret < 1) {
                pabort("can't send spi message");
        }
        if (debug) {
                hex_dump(tx, size, 16, "TX");
                hex_dump(rx, size, 16, "RX");
        }

        if (verbose) printf("Threshold - accelerometer:\n");
        printf("%u\n\n", rx[2]);
        return ret;
}



static int encedo_set_writenvm(void) {
}

static int encedo_set_setmagic(void) {
        int ret = 0;
        uint8_t tx[16];
        uint8_t rx[16];
        unsigned int size;

        memset(tx, 0xFF, sizeof(tx));
        memset(rx, 0xFF, sizeof(rx));

        if (fd < 0) {
                return -1;
        }

        if (oper_arg[0] == 'x') {

                if (sscanf(oper_arg+1, "%x", &size) != 1) {
                        printf("Error: Parser failed\n");
                        return -2;
                }

printf("? %x\n", size);

                tx[0] = 0x61;
		tx[1] = (size >> 24) & 0xFF;
                tx[2] = (size >> 16) & 0xFF;
                tx[3] = (size >> 8) & 0xFF;
                tx[4] = size & 0xFF;
                size = 6;

                ret = spi_transfer(fd, tx, rx, size);
                if (ret < 1) {
                        pabort("can't send spi message");
                }
                if (debug) {
                        hex_dump(tx, size, 16, "TX");
                        hex_dump(rx, size, 16, "RX");
                }
        } else {
                printf("Error: Syntax error\n\n");
        }
        return ret;
}

static int encedo_set_unlockadminmode(void) {
        int ret = 0;
        uint8_t tx[16];
        uint8_t rx[16];
        unsigned int size;

        memset(tx, 0xFF, sizeof(tx));
        memset(rx, 0xFF, sizeof(rx));

        if (fd < 0) {
                return -1;
        }

        if (oper_arg[0] == 'x') {

                if (sscanf(oper_arg+1, "%x", &size) != 1) {
                        printf("Error: Parser failed\n");
                        return -2;
                }

                tx[0] = 0x62;
                tx[1] = (size >> 24) & 0xFF;
                tx[2] = (size >> 16) & 0xFF;
                tx[3] = (size >> 8) & 0xFF;
                tx[4] = size & 0xFF;
                size = 6;

                ret = spi_transfer(fd, tx, rx, size);
                if (ret < 1) {
                        pabort("can't send spi message");
                }
                if (debug) {
                        hex_dump(tx, size, 16, "TX");
                        hex_dump(rx, size, 16, "RX");
                }
        } else {
                printf("Error: Syntax error\n\n");
        }
        return ret;
}

static int encedo_set_lowbat(void) {
        int ret = 0;
        uint8_t tx[16];
        uint8_t rx[16];
        unsigned int size;

        memset(tx, 0xFF, sizeof(tx));
        memset(rx, 0xFF, sizeof(rx));

        if (fd < 0) {
                return -1;
        }

        if (sscanf(oper_arg, "%u", &size) != 1) {
                printf("Error: Parser failed\n");
                return -2;
        }

        if ((size<1) || (size>100)) {
                printf("Error: Syntax error\n");
                return -3;
        }

        tx[0] = 0x63;
        tx[1] = size;
        size = 4;

        ret = spi_transfer(fd, tx, rx, size);
        if (ret < 1) {
                pabort("can't send spi message");
        }
        if (debug) {
                hex_dump(tx, size, 16, "TX");
                hex_dump(rx, size, 16, "RX");
        }
        return ret;
}

static int encedo_set_criticallowbat(void) {
        int ret = 0;
        uint8_t tx[16];
        uint8_t rx[16];
        unsigned int size;

        memset(tx, 0xFF, sizeof(tx));
        memset(rx, 0xFF, sizeof(rx));

        if (fd < 0) {
                return -1;
        }

        if (sscanf(oper_arg, "%u", &size) != 1) {
                printf("Error: Parser failed\n");
                return -2;
        }

        if ((size<1) || (size>100)) {
                printf("Error: Syntax error\n");
                return -3;
        }

        tx[0] = 0x64;
        tx[1] = size;
        size = 4;

        ret = spi_transfer(fd, tx, rx, size);
        if (ret < 1) {
                pabort("can't send spi message");
        }
        if (debug) {
                hex_dump(tx, size, 16, "TX");
                hex_dump(rx, size, 16, "RX");
        }
        return ret;
}

static int encedo_set_accelsensitivity(void) {
        int ret = 0;
        uint8_t tx[16];
        uint8_t rx[16];
        unsigned int size;

        memset(tx, 0xFF, sizeof(tx));
        memset(rx, 0xFF, sizeof(rx));

        if (fd < 0) {
                return -1;
        }

        if (sscanf(oper_arg, "%u", &size) != 1) {
                printf("Error: Parser failed\n");
                return -2;
        }

        if ((size<1) || (size>128)) {
                printf("Error: Syntax error\n");
                return -3;
        }

        tx[0] = 0x65;
        tx[1] = size;
        size = 4;

        ret = spi_transfer(fd, tx, rx, size);
        if (ret < 1) {
                pabort("can't send spi message");
        }
        if (debug) {
                hex_dump(tx, size, 16, "TX");
                hex_dump(rx, size, 16, "RX");
        }
        return ret;
}

static int encedo_set_supervisormode(void) {
        int ret = 0;
        uint8_t tx[16];
        uint8_t rx[16];
        unsigned int size;

        memset(tx, 0xFF, sizeof(tx));
        memset(rx, 0xFF, sizeof(rx));

        if (fd < 0) {
                return -1;
        }

        if (sscanf(oper_arg, "%u", &size) != 1) {
                printf("Error: Parser failed\n");
                return -2;
        }

        if ((size<1) || (size>255)) {
                printf("Error: Syntax error\n");
                return -3;
        }

        tx[0] = 0x66;
        tx[1] = size;
        size = 4;

        ret = spi_transfer(fd, tx, rx, size);
        if (ret < 1) {
                pabort("can't send spi message");
        }
        if (debug) {
                hex_dump(tx, size, 16, "TX");
                hex_dump(rx, size, 16, "RX");
        }
        return ret;
}

static int encedo_set_enableusbport(void) {
}
static int encedo_set_disableusbport(void){
}

static int encedo_set_enablemcu(void) {
        int ret = 0;
        uint8_t tx[16];
        uint8_t rx[16];
        unsigned int size;

        memset(tx, 0xFF, sizeof(tx));
        memset(rx, 0xFF, sizeof(rx));

        if (fd < 0) {
                return -1;
        }

        if (sscanf(oper_arg, "%u", &size) != 1) {
                printf("Error: Parser failed\n");
             	return -2;
        }

        if ((size<1) || (size>10)) {
                printf("Error: Syntax error\n");
                return -3;
        }

        tx[0] = 0x69;
        tx[1] = size;
        size = 4;

        ret = spi_transfer(fd, tx, rx, size);
        if (ret < 1) {
           	pabort("can't send spi message");
        }
        if (debug) {
        	hex_dump(tx, size, 16, "TX");
                hex_dump(rx, size, 16, "RX");
        }
        return ret;
}

static int encedo_set_disablemcu(void) {
        int ret = 0;
        uint8_t tx[16];
        uint8_t rx[16];
        unsigned int size;

        memset(tx, 0xFF, sizeof(tx));
        memset(rx, 0xFF, sizeof(rx));

        if (fd < 0) {
                return -1;
        }

        if (sscanf(oper_arg, "%u", &size) != 1) {
                printf("Error: Parser failed\n");
                return -2;
        }

        if ((size<1) || (size>10)) {
                printf("Error: Syntax error\n");
                return -3;
        }

        tx[0] = 0x6A;
        tx[1] = size;
        size = 4;

        ret = spi_transfer(fd, tx, rx, size);
        if (ret < 1) {
                pabort("can't send spi message");
        }
        if (debug) {
                hex_dump(tx, size, 16, "TX");
                hex_dump(rx, size, 16, "RX");
        }

        return ret;
}

static int encedo_set_erasemcu(void) {
        int ret = 0;
        uint8_t tx[16];
        uint8_t rx[16];
        unsigned int size;

        memset(tx, 0xFF, sizeof(tx));
        memset(rx, 0xFF, sizeof(rx));

        if (fd < 0) {
                return -1;
        }

        if (sscanf(oper_arg, "%u", &size) != 1) {
                printf("Error: Parser failed\n");
                return -2;
        }

        if ((size<1) || (size>10)) {
                printf("Error: Syntax error\n");
                return -3;
        }

        tx[0] = 0x6B;
        tx[1] = size;
        size = 4;

        ret = spi_transfer(fd, tx, rx, size);
        if (ret < 1) {
                pabort("can't send spi message");
        }
        if (debug) {
                hex_dump(tx, size, 16, "TX");
                hex_dump(rx, size, 16, "RX");
        }

        return ret;
}

static int encedo_set_rgb(void) {
        int ret = 0;
        uint8_t tx[16];
        uint8_t rx[16];
        unsigned int size;
	
        memset(tx, 0xFF, sizeof(tx));
        memset(rx, 0xFF, sizeof(rx));

    	if (fd < 0) {
        	return -1;
   	}

	if (oper_arg[0] == '#') {

		if (sscanf(oper_arg+1, "%x", &size) != 1) {
			printf("Error: Parser failed\n");			
			return -2;
		}

                tx[0] = 0x6c;
		tx[1] = (size >> 16) & 0xFF; 
		tx[2] = (size >>8) & 0xFF;
		tx[3] = size & 0xFF;
                size = 5;

	        ret = spi_transfer(fd, tx, rx, size);
        	if (ret < 1) {
                	pabort("can't send spi message");
        	}
        	if (debug) {
                	hex_dump(tx, size, 16, "TX");
                	hex_dump(rx, size, 16, "RX");
        	}
	} else {
		printf("Error: Syntax error\n\n");
	}	
        return ret;
}

static int encedo_set_poweroff(void) {
        int ret = 0;
        uint8_t tx[16];
        uint8_t rx[16];
        unsigned int size;

        memset(tx, 0xFF, sizeof(tx));
        memset(rx, 0xFF, sizeof(rx));

        if (fd < 0) {
                return -1;
        }

        if (oper_arg[0] == 'x') {

                if (sscanf(oper_arg+1, "%x", &size) != 1) {
                        printf("Error: Parser failed\n");
                        return -2;
                }

printf("? %x\n", size);

                tx[0] = 0x6d; //SPICMD_SET_PowerOFF
                tx[1] = (size >> 24) & 0xFF;
                tx[2] = (size >> 16) & 0xFF;
                tx[3] = (size >> 8) & 0xFF;
                tx[4] = size & 0xFF;
                size = 6;

                ret = spi_transfer(fd, tx, rx, size);
                if (ret < 1) {
                        pabort("can't send spi message");
                }
                if (debug) {
                        hex_dump(tx, size, 16, "TX");
                        hex_dump(rx, size, 16, "RX");
                }
        } else {
                printf("Error: Syntax error\n\n");
        }
        return ret;

}


static int spi_init(void) {
  	int ret = 0;
	static uint32_t   mode = SPI_MODE_0;
  	static uint8_t    bits = 8;
  	static uint32_t   speed = 100000;
	uint8_t tx[128];
	uint8_t rx[128];
	int size;

	if (verbose && debug) {
		printf("Device in use: %s\n", device);	
	}
	fd = open(device, O_RDWR);
	if (fd < 0) {
		pabort("can't open device");
  	}  
	/* spi mode	 */
	ret = ioctl(fd, SPI_IOC_WR_MODE32, &mode);
	if (ret == -1) {
		pabort("can't set spi mode");
  	}	
	ret = ioctl(fd, SPI_IOC_RD_MODE32, &mode);
	if (ret == -1) {
		pabort("can't get spi mode");
  	}	
	/* bits per word */
	ret = ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
	if (ret == -1) {
		pabort("can't set bits per word");
  	}
	ret = ioctl(fd, SPI_IOC_RD_BITS_PER_WORD, &bits);
	if (ret == -1) {
		pabort("can't get bits per word");
  	}
	/* max speed hz */
	ret = ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);
	if (ret == -1) {
		pabort("can't set max speed hz");
  	}
	ret = ioctl(fd, SPI_IOC_RD_MAX_SPEED_HZ, &speed);
	if (ret == -1) {
		pabort("can't get max speed hz");
  	}
  
  	if (verbose && debug) {
    		printf("spi mode: 0x%x\n", mode);
    		printf("bits per word: %d\n", bits);
    		printf("max speed: %d Hz (%d KHz)\n", speed, speed/1000); 
  	}

  	return ret;
}


static int spi_transfer(int fd, uint8_t const *tx, uint8_t const *rx, size_t len) {

        struct spi_ioc_transfer tr = {
                .tx_buf = (unsigned long)tx,
                .rx_buf = (unsigned long)rx,
                .len = len,
        };

        return ioctl(fd, SPI_IOC_MESSAGE(1), &tr);
}


static void pabort(const char *s) {
	perror(s);
	abort();
}

static void print_usage(const char *prog) {

	printf("Version: 1.4 " __DATE__ " " __TIME__ "\n");
	printf("Usage: %s [-vDdoapbh]\n", prog);
	puts("  -v --verbose  verbose mode (debug)\n"
	     "  -D --debug    debug SPI RAW communication\n"
	     "  -d --dev      SPI device to use (default: /dev/spidev0.1)\n"
	     "  -o --oper     operation (e.g. GET_DeviceID, GET_DeviceInfo)\n"
	     "  -a --arg      operation arguments\n"	
	     "  -b --blfile   bootloader source file to upload\n"
	     "  -p --blport   bootloader output device\n"
	     "  -h --help     this help\n");
	     
	exit(1);
}

static void parse_opts(int argc, char *argv[]) {
	int c;

	while (1) {
		static const struct option lopts[] = {
			{ "dev",     1, 0, 'd' },
			{ "debug",   0, 0, 'D' },
			{ "oper",    1, 0, 'o' },
			{ "arg",     1, 0, 'a' },
			{ "blfile",  1, 0, 'b' },
			{ "blport",  1, 0, 'p' },
			{ "verbose", 0, 0, 'v' },
			{ "help",    0, 0, 'h' },
			{ NULL,      0, 0, 0 },
		};

		c = getopt_long(argc, argv, "b:p:d:o:a:vhD", lopts, NULL);

		if (c == -1)
			break;

		switch (c) {
		case 'd':
			snprintf(device, sizeof(device)-1, "%s", optarg);
			break;
                case 'o':
                        snprintf(oper, sizeof(oper)-1, "%s", optarg);
                        break;
                case 'a':
                        snprintf(oper_arg, sizeof(oper_arg)-1, "%s", optarg);
                        break;
		case 'b':
                        snprintf(blfile, sizeof(blfile)-1, "%s", optarg);
                        break;
		case 'p':
                        snprintf(blport, sizeof(blport)-1, "%s", optarg);
                        break;
		case 'v':
			verbose = 1;
			break;
                case 'D':
                        debug = 1;
                        break;
		case 'h':
		default:
			print_usage(argv[0]);
			break;
		}
	}
}


static void hex_dump(const void *src, size_t length, size_t line_size, char *prefix) {
	int i = 0;
	const unsigned char *address = src;
	const unsigned char *line = address;
	unsigned char c;

	printf("%s | ", prefix);
	while (length-- > 0) {
		printf("%02X ", *address++);
		if (!(++i % line_size) || (length == 0 && i % line_size)) {
			if (length == 0) {
				while (i++ % line_size)
					printf("__ ");
			}
			printf(" | ");  /* right close */
			while (line < address) {
				c = *line++;
				printf("%c", (c < 33 || c == 255) ? 0x2E : c);
			}
			printf("\n");
			if (length > 0)
				printf("%s | ", prefix);
		}
	}
}

/*
 *  Unescape - process hexadecimal escape character
 *      converts shell input "\x23" -> 0x23
 */
static int unescape(char *_dst, char *_src, size_t len) {
	int ret = 0;
	char *src = _src;
	char *dst = _dst;
	unsigned int ch;

	while (*src) {
		if (*src == '\\' && *(src+1) == 'x') {
			sscanf(src + 2, "%2x", &ch);
			src += 4;
			*dst++ = (unsigned char)ch;
		} else {
			*dst++ = *src++;
		}
		ret++;
	}
	return ret;
}



// Translation Table as described in RFC1113
static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Translation Table to decode (created by author)
static const char cd64[]="|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";

// Encode 3 8-bit binary bytes as 4 '6-bit' characters
//static 
void base64_encodeblock( unsigned char in[3], unsigned char out[4], int len )
{
    out[0] = cb64[ in[0] >> 2 ];
    out[1] = cb64[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
    out[2] = (unsigned char) (len > 1 ? cb64[ ((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6) ] : '=');
    out[3] = (unsigned char) (len > 2 ? cb64[ in[2] & 0x3f ] : '=');
}

// Decode 4 '6-bit' characters into 3 8-bit binary bytes
static void base64_decodeblock( unsigned char in[4], unsigned char out[3] )
{   
    out[ 0 ] = (unsigned char ) (in[0] << 2 | in[1] >> 4);
    out[ 1 ] = (unsigned char ) (in[1] << 4 | in[2] >> 2);
    out[ 2 ] = (unsigned char ) (((in[2] << 6) & 0xc0) | in[3]);
}


int base64_encode(unsigned char *dst, int dst_max, unsigned char *src, int src_len) {
  unsigned char in[3], out[4]={0,0,0,0};
  int tlen = 0, len;
 
  if (dst == NULL) 
    return 0;
    
  while( src_len ) {
		if (dst_max <4) {
				return -1;
		}
    len = 3;
    if (src_len < len) len = src_len;
    in[1] = 0; in[2] = 0;
    memcpy(in, src, len);
    base64_encodeblock( in, out, len );
    memcpy(dst, out, 4);
    src += len;
    dst += 4;    
		dst_max -= 4;
    tlen += 4;
    src_len -= len;
    *dst = '\0';
  }  
  return tlen;
}


int convert_length_bin2base64(int bin_len) {
	while(bin_len % 3) {
			bin_len++;
	}
	return (bin_len*4)/3;
}




/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset) {

        int i;
        int gap;
        const u_char *ch;

        /* offset */
        printf("%05d   ", offset);

        /* hex */
        ch = payload;
        for(i = 0; i < len; i++) {
                printf("%02x ", *ch);
                ch++;
                /* print extra space after 8th byte for visual aid */
                if (i == 7)
                        printf(" ");
        }
        /* print space to handle line less than 8 bytes */
        if (len < 8)
                printf(" ");

        /* fill hex gap with spaces if not full line */
        if (len < 16) {
                gap = 16 - len;
                for (i = 0; i < gap; i++) {
                        printf("   ");
                }
        }
        printf("   ");

        /* ascii (if printable) */
        ch = payload;
        for(i = 0; i < len; i++) {
                if (isprint(*ch))
                        printf("%c", *ch);
                else
                        printf(".");
                ch++;
        }

        printf("\n");

  return;
}

static int set_interface_attribs(int fd, int speed)
{
    struct termios tty;

    if (tcgetattr(fd, &tty) < 0) {
        printf("Error from tcgetattr: %s\n", strerror(errno));
        return -1;
    }

    cfsetospeed(&tty, (speed_t)speed);
    cfsetispeed(&tty, (speed_t)speed);

    tty.c_cflag |= (CLOCAL | CREAD);    /* ignore modem controls */
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;         /* 8-bit characters */
    tty.c_cflag &= ~PARENB;     /* no parity bit */
    tty.c_cflag &= ~CSTOPB;     /* only need 1 stop bit */
    tty.c_cflag &= ~CRTSCTS;    /* no hardware flowcontrol */

    /* setup for non-canonical mode */
    tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
    tty.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    tty.c_oflag &= ~OPOST;

    /* fetch bytes as they become available */
    tty.c_cc[VMIN] = 1;
    tty.c_cc[VTIME] = 1;

    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        printf("Error from tcsetattr: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

//this function is dirty, just a PoC
int bootloader_send_hex(int fd_cdc, int fd_hexfile)
{
    char txbuf[512+1];      //check comment below
    int tbw, cnt;
    unsigned char buf[80];
    int rdlen, wlen;
    int ret = 0, sync = 0;

    /*baudrate 115200, 8 bits, no parity, 1 stop bit */
    set_interface_attribs(fd_cdc, B115200);

    //Comment: encedo_bootloader till version 1.2 supports byte-by-byte transfers only over USB!
    //         calling write() with more than 1 byte crash bootloader.

    printf("\nSyncing... ");
    cnt = 0;
    do {
      	rdlen = read(fd_cdc, buf, sizeof(buf) - 1);
        if (rdlen > 0) {
            buf[rdlen] = 0;
	    if (strstr(buf, "WAITING") != NULL) {
		sync = 1;
		break;
	    }
        } else if (rdlen < 0) {
            printf("Error from read: %d: %s\n", rdlen, strerror(errno));
	    break;
        } else {
            printf("Timeout from read OR closed fd\n");
            break;
        }
	cnt++;
    } while(cnt < 10);	
   
    if (sync == 0) {
    	return -3;
    }

    printf("\nAll set, start sending file...\n");

    cnt = 0;
    do {
        tbw = read(fd_hexfile, txbuf, sizeof(txbuf)-1);
        if (tbw == 0) {
                break;  //EOF
        }
        if (tbw < 0) {
                printf("  TBW: %d\r\n", tbw);
                ret = -1;
                break;
        }

        wlen = write(fd_cdc, txbuf, tbw);
        if (wlen != tbw) {
                printf("Error from write: %d, %d\n", wlen, errno);
                ret = -2;
                break;
        }
	    
        cnt += wlen;
	if ((cnt % 32768) == 0) printf(".");
    } while (tbw > 0);
    
    printf("\n");
    return ret;
}


int bootloader_preview(int fd_cdc) 
{

    int cnt;
    unsigned char buf[80];
    int rdlen, wlen;
    int ret = 0;

    /*baudrate 115200, 8 bits, no parity, 1 stop bit */
    set_interface_attribs(fd_cdc, B115200);

    printf("\nAll set, what do we have here? ...\n");

    cnt = 0;
    do {
        rdlen = read(fd_cdc, buf, sizeof(buf) - 1);
        if (rdlen > 0) {
            buf[rdlen] = 0;
            printf("%s", buf);
        } else if (rdlen <= 0) {
            break;
        }

        cnt++;
    } while (1);

    printf("\n");
    return 0;
}


/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len) {

        int len_rem = len;
        int line_width = 16;                    /* number of bytes per line */
        int line_len;
        int offset = 0;                                 /* zero-based offset counter */
        const u_char *ch = payload;

        if (len <= 0)
                return;

        /* data fits on one line */
        if (len <= line_width) {
                print_hex_ascii_line(ch, len, offset);
                return;
        }

        /* data spans multiple lines */
        for ( ;; ) {
                /* compute current line length */
                line_len = line_width % len_rem;
                /* print line */
                print_hex_ascii_line(ch, line_len, offset);
                /* compute total remaining */
                len_rem = len_rem - line_len;
                /* shift pointer to remaining bytes to print */
                ch = ch + line_len;
                /* add offset */
                offset = offset + line_width;
                /* check if we have line width chars or less */
                if (len_rem <= line_width) {
                        /* print last line and get out */
                        print_hex_ascii_line(ch, len_rem, offset);
                        break;
                }
        }

  return;
}



