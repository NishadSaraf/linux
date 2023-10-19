/*
 * Copyright (C) 2023, Xilinx Inc
 *
 * Licensed under Apache License 2.0 or General Public License 2.0
 *
 * Header file for Accelerated FPGA Versal Boards
 */

#ifndef _VMGMT_XGQ_CMD_H
#define _VMGMT_XGQ_CMD_H
#include <linux/types.h>

/* preprocessors and definitions */
#define XGQ_ASSERT_CONCAT_(a, b) a##b
#define XGQ_ASSERT_CONCAT(a, b) XGQ_ASSERT_CONCAT_(a, b)

/*Create an artifitial assertion via a bad divide by zero assertion.*/
#define XGQ_STATIC_ASSERT(e,m) \
	enum { XGQ_ASSERT_CONCAT(xgq_assert_line_, __LINE__) = 1/(int)(!!(e)) }

#define VMR_MAGIC_NO	0x564D5230 /* VMR0 */
#define XGQ_SQ_CMD_NEW	1
/* TO DO:- Do we need to add the full descriptive explanation and comments
 * about doorbell register ?
 */
#define XGQ_ENTRY_NEW_FLAG_MASK         0x80000000
#define XGQ_COM_Q1_SLOT_SIZE    (sizeof(struct xgq_com_queue_entry)) // NOLINT

/*Structure data field masks*/
#define XGQ_MASK_FLASH_TYPE	GENMASK(7,4)
#define XGQ_MASK_PID		GENMASK(15,0)
#define ONE_QUAD_WORD_OFFSET	(8)

/*TO DO:- Host driver is client and the SERVER macro should be removed; */
/* enumerations and definitions */

/*
 * multi boot operation request types
 *
 */
enum xgq_cmd_vmr_control_type {
	XGQ_CMD_VMR_QUERY       = 0x0,
	XGQ_CMD_BOOT_DEFAULT    = 0x1,
	XGQ_CMD_BOOT_BACKUP     = 0x2,
	XGQ_CMD_PROGRAM_SC      = 0x3,
};

/* Opcode encoding rules:
 * | 15 ------ 11 | 10 ----- 8 | 7 ----- 0 |
 * +--------------+------------+-----------+
 * |   Reserved   |    Type    |  OP's ID  |
 * +--------------+------------+-----------+
 */
enum xgq_cmd_opcode {
	/* management command type */
	XGQ_CMD_OP_LOAD_XCLBIN          = 0x0,
	XGQ_CMD_OP_CONFIGURE            = 0x1,
	XGQ_CMD_OP_GET_LOG_PAGE         = 0x8,
	XGQ_CMD_OP_DOWNLOAD_PDI         = 0xa,
	XGQ_CMD_OP_LOAD_APUBIN          = 0xd,
	XGQ_CMD_OP_VMR_CONTROL          = 0xe,
	XGQ_CMD_OP_PROGRAM_SCFW         = 0xf,
	/* common command type */
	XGQ_CMD_OP_IDENTIFY		= 0x202,
};

/*
 *Flash type command
 */
enum xgq_cmd_flash_type {
	XGQ_CMD_FLASH_DEFAULT           = 0x0,
	XGQ_CMD_FLASH_NO_BACKUP         = 0x1,
	XGQ_CMD_FLASH_TO_LEGACY         = 0x2,
};

/**
 * log page type
 */
enum xgq_cmd_log_page_type {
        XGQ_CMD_LOG_AF_CHECK    = 0x0,
        XGQ_CMD_LOG_FW          = 0x1,
        XGQ_CMD_LOG_INFO        = 0x2,
        XGQ_CMD_LOG_AF_CLEAR    = 0x3,
        XGQ_CMD_LOG_ENDPOINT    = 0x4,
        XGQ_CMD_LOG_TASK_STATS  = 0x5,
        XGQ_CMD_LOG_MEM_STATS   = 0x6,
        XGQ_CMD_LOG_SYSTEM_DTB  = 0x7,
        XGQ_CMD_LOG_PLM_LOG     = 0x8,
        XGQ_CMD_LOG_APU_LOG     = 0x9,
        XGQ_CMD_LOG_SHELL_INTERFACE_UUID        = 0xa,
};

/* structures and definitions */

/*
 * struct xgq_cmd_data_payload: data request payload command
 *
 * @address: data that needs to be transferred
 * @size: data size
 * @flash_type: flash_type Default,No Backup or Legacy
 * ----flash_type field encoding-----
 * | rsvd1 | flash_type | addr_type |
 * +--------------------------------+
 * | 31---8| 7--------4 | 3-------0 |
 */
struct xgq_cmd_data_payload {
	u64 address;
	u32 size;
	u32 remain_size;
	u32 flash_type;
	u32 pad1;
	u64 priv;
};

/**
 * struct xgq_cmd_log_payload: log_page request command
 *
 * @address:    pre-allocated log data, device writes log data at this address
 * @size:       size of pre-allocated log data
 * @offset:     offset of returned device data
 * @pid:        log_page page id
 * ------pid field encoding------
 * |  rsvd1 | addr_type |  pid  |
 * +---------------------------+
 * | 31---19| 18-----16 | 15--0 |
 *
 * This payload is used for log_page and sensor data report.
 */
/*TO DO:- Bit fields masking*/
struct xgq_cmd_log_payload {
        u64 address;
        u32 size;
        u32 offset;
	u32 pid;
	u32 pad;
};

/**
 * struct xgq_cmd_vmr_control_payload: vmr controlling ops
 *
 * @req_type:           request type
 */

/*TO DO:- Bit fields masking*/
struct xgq_cmd_vmr_control_payload {
        uint32_t req_type:8;
        uint32_t debug_level:3;
        uint32_t debug_type:5;
        uint32_t rsvd:16;
};

/*
 * struct xgq_cmd_sq_hdr: XGQ submission queue entry header format
 *
 * @opcode:     [15-0]  command opcode identifying specific command
 * @count:      [30-16] number of bytes representing packet payload
 * @state:      [31]    flag indicates this is a new entry
 * @cid:                unique command id
 * @rsvd:               reserved for future use
 * @cu_domain:  [3-0]   CU domain for certain start CU op codes
 * @cu_idx:     [11-0]  CU index for certain start CU op codes
 *
 * Any command in XGQ submission queue shares same command header.
 * An command ID is used to identify the command. When the command
 * is completed, the same command ID is put into the completion
 * queue entry.
 *
 * Please declare this struct at the begin of a submission queue entry
 */

/*TO DO:- Bit fields masking*/
struct xgq_cmd_sq_hdr {
	union {
		struct {
			u32 opcode:16; /* [15-0]   */
			u32 count:15;  /* [30-16] */
			u32 state:1;   /* [31] */
			u16 cid;
			union {
				u16 rsvd;
				struct {
					u16 cu_idx:12;
					u16 cu_domain:4;
				};
			};
		};
		u32 header[2]; // NOLINT
	};
};
XGQ_STATIC_ASSERT(sizeof(struct xgq_cmd_sq_hdr) == 8, "xgq_cmd_sq_hdr structure no longer is 8 bytes in size");

/**
 * struct xgq_cmd_cq_hdr: XGQ completion queue entry header format
 *
 * @cid:        unique command id
 * @cstate:     command state
 * @specific:   flag indicates there is command specific info in result
 * @state:      flag indicates this is a new entry
 *
 * This is the header of the completion queue entry. A generic command
 * state is put into cstate. The command is identified by cid which
 * matches the cid in submission queue.
 *
 * Please declare this struct at the begin of a completion queue entry
 */

/*TO DO:- Bit fields masking*/
struct xgq_cmd_cq_hdr {
	union {
		struct {
			u16 cid;
			u16 cstate:14;
			u16 specific:1;
			u16 state:1;
		};
		u32 header[1]; // NOLINT
	};
};
XGQ_STATIC_ASSERT(sizeof(struct xgq_cmd_cq_hdr) == 4, "xgq_cmd_cq_hdr structure no longer is 4 bytes in size");

/*
 * struct xgq_cmd_sq: vmr xgq submission command abstraction
 *
 * @hdr: vmr xgq command header
 * @pdi_payload: pdi data payload
 * @xclbin_payload:xclbin data payload
 */
struct xgq_cmd_sq {
	struct xgq_cmd_sq_hdr hdr;
	union {
		struct xgq_cmd_log_payload		log_payload;
		struct xgq_cmd_data_payload		pdi_payload;
		struct xgq_cmd_data_payload		xclbin_payload;
		struct xgq_cmd_vmr_control_payload	vmr_control_payload;
	};
};

/*
 * struct xgq_cmd_cq_default_payload: vmr default completion payload
 *
 * @result: result code
 */
struct xgq_cmd_cq_default_payload {
	u32 resvd0;
	u32 resvd1;
};

/*
 * struct xgq_cmd_cq_vmr_payload: vmr device status payload
 *
 * bitfields for indicting flash partition statistics
 * for vmr device status.
 */
/*TO DO:- Bit fields masking*/
struct xgq_cmd_cq_vmr_payload {
	u16 has_fpt:1;
	u16 has_fpt_recovery:1;
	u16 boot_on_default:1;
	u16 boot_on_backup:1;
	u16 boot_on_recovery:1;
	u16 has_extfpt:1;
	u16 has_ext_xsabin:1;
	u16 has_ext_scfw:1;
	u16 has_ext_sysdtb:1;
	u16 ps_is_ready:1;
	u16 pl_is_ready:1;
	u16 sc_is_ready:1;
	u16 resvd1:4;
	u16 current_multi_boot_offset;
	u32 debug_level:3;
	u32 program_progress:7;
	u16 resvd2:6;
	u16 boot_on_offset;
};

/*
 * struct xgq_cmd_cq_vmr_identify_payload: Identify Command payload
 *
 * VMR Identify Command major and minor numbers
 */
struct xgq_cmd_cq_vmr_identify_payload {
	u16 ver_major;
	u16 ver_minor;
	u32 resvd;
};

/**
 * struct xgq_cmd_cq_log_page_payload: vmr log page completion payload
 *
 * @count:      how many data returned in bytes
 */
struct xgq_cmd_cq_log_page_payload {
        uint32_t count;
        uint32_t resvd1;
};

/*
 * struct xgq_cmd_cq: vmr completion command
 *
 * @hdr: vmr completion command header
 * @default_payload: return status value
 * @vmr_payload: Flash partition stats payload
 * @vmr_identify_payload: version number of vmr device
 */
struct xgq_cmd_cq {
	struct xgq_cmd_cq_hdr hdr;
	union {
		struct xgq_cmd_cq_default_payload       cq_default_payload;
		struct xgq_cmd_cq_vmr_payload           cq_vmr_payload;
		struct xgq_cmd_cq_vmr_identify_payload  cq_vmr_identify_payload;
		struct xgq_cmd_cq_log_page_payload	cq_log_payload;
	};
	u32 rcode;
};
XGQ_STATIC_ASSERT(sizeof(struct xgq_cmd_cq) == 16, "xgq_cmd_cq has to be 16 bytes in size");

/* XGQ memory partition table, should be positioned at shared memory offset 0,
 * and inited by VMR software on RPU device.
 * @vmr_magic_no:       the magic no.
 * @ring_buffer_off:    the offset of xgq ring buffer inited by xgq server
 * @ring_buffer_len:    the length of xgq ring buffer inited by xgq server
 * @vmr_status_off:     the offset of vmr device status
 * @vmr_status_len:     the length of vmr device status
 * @log_msg_index:      the current index of ring buffer log
 * @log_msg_buf_off:    the offset of dbg log
 * @log_msg_buf_len:    the length of dbg log
 * @vmr_data_start:     the offset of data buffer started
 * @vmr_data_end:       the offset of data buffer ended
 */
struct vmr_shared_mem {
	u32	vmr_magic_no;
	u32	ring_buffer_off;
	u32	ring_buffer_len;
	u32	vmr_status_off;
	u32	vmr_status_len;
	u32	log_msg_index;
	u32	log_msg_buf_off;
	u32	log_msg_buf_len;
	u32	vmr_data_start;
	u32	vmr_data_end;
};

struct xgq_com_queue_entry {
	union {
		struct {
			struct xgq_cmd_cq_hdr hdr;
			u32 result;
			u32 resvd;
			u32 rcode;
		};
		u32 data[4]; // NOLINT
	};
};
XGQ_STATIC_ASSERT(sizeof(struct xgq_com_queue_entry) == 16, "xgq_com_queue_entry structure no longer is 16 bytes in size");

/* Software representation of a single ring buffer. */
struct xgq_ring {
        struct xgq *xr_xgq; /* pointing back to parent q */
        uint32_t xr_slot_num;
        uint32_t xr_slot_sz;
        uint32_t xr_produced;
        uint32_t xr_consumed;

        uint64_t xr_produced_addr;
        uint64_t xr_consumed_addr;
        uint64_t xr_slot_addr;
};

/* Software representation of a single XGQ. */
#define XGQ_DOUBLE_READ         (1UL << 1) // NOLINT
#define XGQ_IN_MEM_PROD         (1UL << 2) // NOLINT
struct xgq {
        uint64_t xq_io_hdl;
        uint64_t xq_header_addr;
        uint32_t xq_flags;
	struct xgq_ring xq_sq ____cacheline_aligned_in_smp;
        struct xgq_ring xq_cq ____cacheline_aligned_in_smp;
};
#define XGQ_NEED_DOUBLE_READ(xgq)       (((xgq)->xq_flags & XGQ_DOUBLE_READ) != 0)
#define XGQ_IS_IN_MEM_PROD(xgq)         (((xgq)->xq_flags & XGQ_IN_MEM_PROD) != 0)

/* Prototypes and definitions */
void xgq_reg_write32(uint64_t io_hdl, uint64_t addr, uint32_t val);
uint32_t xgq_reg_read32(uint64_t io_hdl, uint64_t addr);
void xgq_mem_write32(uint64_t io_hdl, uint64_t addr, uint32_t val);
uint32_t xgq_mem_read32(uint64_t io_hdl, uint64_t addr);
int xgq_consume(struct xgq *xgq, uint64_t *slot_addr);
int xgq_produce(struct xgq *xgq, uint64_t *slot_addr);
void xgq_notify_peer_produced(struct xgq *xgq);
void xgq_notify_peer_consumed(struct xgq *xgq);
int xgq_attach(struct xgq *xgq, uint64_t flags, uint64_t io_hdl, uint64_t ring_addr,
                             uint64_t sq_produced, uint64_t cq_produced);
#endif
