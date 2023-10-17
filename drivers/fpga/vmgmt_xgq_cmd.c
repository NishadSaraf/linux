#include <asm/io.h>
#include <linux/module.h>
#include <linux/types.h>

#include "vmgmt_xgq_cmd.h"

#define XGQ_TRUE        1
#define XGQ_FALSE       0

void xgq_mem_write32(u64 io_hdl, u64 addr, u32 val)
{
        iowrite32(val, (void __iomem *)addr);
}

void xgq_reg_write32(u64 io_hdl, u64 addr, u32 val)
{
        iowrite32(val, (void __iomem *)addr);
}

u32 xgq_mem_read32(u64 io_hdl, u64 addr)
{
        return ioread32((void __iomem *)addr);
}

u32 xgq_reg_read32(u64 io_hdl, u64 addr)
{
        return ioread32((void __iomem *)addr);
}

static inline u32 xgq_read32(u64 io_hdl, u64 addr, int is_mem)
{
        return xgq_reg_read32(io_hdl, addr);
}

static inline void xgq_write32(u64 io_hdl, u64 addr, u32 val, int is_mem)
{
        xgq_reg_write32(io_hdl, addr, val);
}

/*
 * Currently, this is only used as a workaround for the BRAM read/write collision HW
 * issue on MB ERT, which will cause ERT to read incorrect value from CQ. We only
 * trust the value until we read twice and got the same value.
 */
static inline u32 xgq_double_read32(u64 io_hdl, u64 addr, int is_mem)
{
        u32 val[2];
        int i = 0;

        val[1] = xgq_read32(io_hdl, addr, is_mem);
        val[0] = val[1] - 1;
        while (val[0] != val[1])
                val[i++ & 0x1] = xgq_read32(io_hdl, addr, is_mem);
        return val[0];
}

/*
 * One XGQ consists of one submission (SQ) and one completion ring (CQ) buffer shared by one client
 * and one server. Client send request through SQ to server, which processes it and send back
 * response through CQ.
 */
#define XGQ_ALLOC_MAGIC			0x5847513F	/* XGQ? */
#define XGQ_MAJOR			1
#define XGQ_MINOR			0
#define XGQ_MIN_NUM_SLOTS		2
#define XGQ_VERSION			((XGQ_MAJOR<<16)+XGQ_MINOR)
#define GET_XGQ_MAJOR(version)		(version>>16)
#define GET_XGQ_MINOR(version)		(version&0xFFFF)

/*TO DO:- redo the comment with upstreaming format*/
/*
 * Meta data shared b/w client and server of XGQ
 */
struct xgq_header {
	u32 xh_magic; /* Always the first member */
	u32 xh_version;

	/* SQ and CQ share the same num of slots. */
	u32 xh_slot_num;

	u32 xh_sq_offset;
	u32 xh_sq_slot_size;
	u32 xh_cq_offset;
	/* CQ slot size and format is tied to XGQ version. */

	/*
	 * Consumed pointer for both SQ and CQ are here since they don't generate interrupt,
	 * so no need to be a register.
	 */
	u32 xh_sq_consumed;
	u32 xh_cq_consumed;

	u32 xh_flags;

	/*
	 * On some platforms, there is no dedicated producer pointer register. We can use
	 * below in-mem version to communicate b/w the peers.
	 */
	u32 xh_sq_produced;
	u32 xh_cq_produced;
};

/* Software representation of a single XGQ. */
#define XGQ_DOUBLE_READ		(1UL << 1) // NOLINT
#define XGQ_IN_MEM_PROD		(1UL << 2) // NOLINT

/*
 * XGQ implementation details and helper routines.
 */

static inline size_t xgq_ring_len(size_t nslots, size_t slotsz)
{
	return sizeof(struct xgq_header) + nslots * (slotsz + sizeof(struct xgq_com_queue_entry));
}

static inline void xgq_copy_to_ring(u64 io_hdl, void *buf, u64 tgt, size_t len)
{
	size_t i = 0;
	u32 *src = (u32 *)buf;

	for (i = 0; i < len / 4; i++, tgt += 4)
		xgq_mem_write32(io_hdl, tgt, src[i]);
}

static inline void xgq_copy_from_ring(u64 io_hdl, void *buf, u64 src, size_t len)
{
	size_t i = 0;
	u32 *tgt = (u32 *)buf;

	for (i = 0; i < len / 4; i++, src += 4)
		tgt[i] = xgq_mem_read32(io_hdl, src);
}

static inline void xgq_init_ring(struct xgq *xgq, struct xgq_ring *ring,
				 u64 produced, u64 consumed, u64 slots,
				 u32 slot_num, u32 slot_size)
{
	ring->xr_xgq = xgq;
	ring->xr_produced_addr = produced;
	ring->xr_consumed_addr = consumed;
	ring->xr_slot_addr = slots;
	ring->xr_slot_sz = slot_size;
	ring->xr_slot_num = slot_num;
	ring->xr_produced = ring->xr_consumed = 0;
}

static inline int xgq_ring_full(struct xgq_ring *ring)
{
	return (ring->xr_produced - ring->xr_consumed) >= ring->xr_slot_num;
}

static inline int xgq_ring_empty(struct xgq_ring *ring)
{
	return ring->xr_produced == ring->xr_consumed;
}

static inline void xgq_ring_read_produced(u64 io_hdl, struct xgq_ring *ring)
{
	if (unlikely(XGQ_NEED_DOUBLE_READ(ring->xr_xgq))) {
		ring->xr_produced = xgq_double_read32(io_hdl, ring->xr_produced_addr,
						      XGQ_IS_IN_MEM_PROD(ring->xr_xgq));
	} else {
		ring->xr_produced = xgq_read32(io_hdl, ring->xr_produced_addr,
					       XGQ_IS_IN_MEM_PROD(ring->xr_xgq));
	}
}

static inline void xgq_ring_write_produced(u64 io_hdl, struct xgq_ring *ring)
{
	xgq_write32(io_hdl, ring->xr_produced_addr, ring->xr_produced,
		    XGQ_IS_IN_MEM_PROD(ring->xr_xgq));
}

static inline void xgq_ring_read_consumed(u64 io_hdl, struct xgq_ring *ring)
{
	if (unlikely(XGQ_NEED_DOUBLE_READ(ring->xr_xgq)))
		ring->xr_consumed = xgq_double_read32(io_hdl, ring->xr_consumed_addr, XGQ_TRUE);
	else
		ring->xr_consumed = xgq_mem_read32(io_hdl, ring->xr_consumed_addr);
}

static inline void xgq_ring_write_consumed(u64 io_hdl, struct xgq_ring *ring)
{
	xgq_mem_write32(io_hdl, ring->xr_consumed_addr, ring->xr_consumed);
}

static inline u64 xgq_ring_slot_ptr_produced(struct xgq_ring *ring)
{
	return ring->xr_slot_addr +
		/*
		 * In reality, below multiplication of two 32-bit ints will not overflow.
		 * So, keep it as-is, instead of doing 64-bit mutiplication, which is very
		 * slow on 32-bit CPU, e.g., Microblaze.
		 */
		ring->xr_slot_sz * (ring->xr_produced & (ring->xr_slot_num - 1));
}

static inline u64 xgq_ring_slot_ptr_consumed(struct xgq_ring *ring)
{
	return ring->xr_slot_addr +
		/*
		 * In reality, below multiplication of two 32-bit ints will not overflow.
		 * So, keep it as-is, instead of doing 64-bit mutiplication, which is very
		 * slow on 32-bit CPU, e.g., Microblaze.
		 */
		ring->xr_slot_sz * (ring->xr_consumed & (ring->xr_slot_num - 1));
}

static inline int xgq_can_produce(struct xgq *xgq)
{
/* Host driver is XGQ_CLIENT and VMR is XGQ_SERVER */
#ifdef XGQ_SERVER
	struct xgq_ring *ring = &xgq->xq_cq;
#else
	struct xgq_ring *ring = &xgq->xq_sq;
#endif

	if (likely(!xgq_ring_full(ring)))
		return XGQ_TRUE;
	xgq_ring_read_consumed(xgq->xq_io_hdl, ring);
	return !xgq_ring_full(ring);
}

static inline int xgq_can_consume(struct xgq *xgq)
{
/* Host driver is XGQ_CLIENT and VMR is XGQ_SERVER */
#ifdef XGQ_SERVER
	struct xgq_ring *ring = &xgq->xq_sq;
#else
	struct xgq_ring *ring = &xgq->xq_cq;
#endif

	if (likely(!xgq_ring_empty(ring)))
		return XGQ_TRUE;
	xgq_ring_read_produced(xgq->xq_io_hdl, ring);
	return !xgq_ring_empty(ring);
}

/*
 * Fast forward to where we left. Used only during xgq_attach().
 */
static inline void xgq_fast_forward(struct xgq *xgq, struct xgq_ring *ring)
{
	xgq_ring_read_produced(xgq->xq_io_hdl, ring);
	xgq_ring_read_consumed(xgq->xq_io_hdl, ring);
}

/*
 * Set consumed to be the same as produced to ignore any existing commands. And there should not
 * be any left over commands anyway. Used only during xgq_alloc().
 */
static inline void xgq_soft_reset(struct xgq *xgq, struct xgq_ring *ring)
{
	xgq_ring_read_produced(xgq->xq_io_hdl, ring);
	ring->xr_consumed = ring->xr_produced;
	xgq_ring_write_consumed(xgq->xq_io_hdl, ring);
}

int xgq_attach(struct xgq *xgq, u64 flags, u64 io_hdl, u64 ring_addr,
                             u64 sq_produced, u64 cq_produced)
{
        struct xgq_header hdr = {};
        u32 nslots;
        u64 sqprod, cqprod;

        xgq_copy_from_ring(xgq->xq_io_hdl, &hdr, ring_addr, sizeof(u32));
        // Magic number must show up to confirm the header is fully initialized
        if (hdr.xh_magic != XGQ_ALLOC_MAGIC)
                return -EAGAIN;

        xgq_copy_from_ring(xgq->xq_io_hdl, &hdr, ring_addr, sizeof(struct xgq_header));
        if (GET_XGQ_MAJOR(hdr.xh_version) != XGQ_MAJOR)
                return -EOPNOTSUPP;

        nslots = hdr.xh_slot_num;
        if ((nslots < XGQ_MIN_NUM_SLOTS) || (nslots & (nslots - 1)))
                return -EPROTO;

        xgq->xq_flags = 0;
        xgq->xq_flags |= flags;
        xgq->xq_flags |= (hdr.xh_flags & XGQ_DOUBLE_READ);
        xgq->xq_flags |= (hdr.xh_flags & XGQ_IN_MEM_PROD);

        if (XGQ_IS_IN_MEM_PROD(xgq)) {
                /* Passed-in sq/cq producer pointer will be ignored. */
                sqprod = ring_addr + offsetof(struct xgq_header, xh_sq_produced);
                cqprod = ring_addr + offsetof(struct xgq_header, xh_cq_produced);
        } else {
                sqprod = sq_produced;
                cqprod = cq_produced;
        }
        xgq_init_ring(xgq, &xgq->xq_sq, sqprod,
                      ring_addr + offsetof(struct xgq_header, xh_sq_consumed),
                      ring_addr + hdr.xh_sq_offset,
                      hdr.xh_slot_num, hdr.xh_sq_slot_size);
        xgq_init_ring(xgq, &xgq->xq_cq, cqprod,
                      ring_addr + offsetof(struct xgq_header, xh_cq_consumed),
                      ring_addr + hdr.xh_cq_offset,
                      hdr.xh_slot_num, sizeof(struct xgq_com_queue_entry));

        xgq_fast_forward(xgq, &xgq->xq_sq);
        xgq_fast_forward(xgq, &xgq->xq_cq);
        return 0;
}

int xgq_produce(struct xgq *xgq, u64 *slot_addr)
{
/* Host driver is XGQ_CLIENT and VMR is XGQ_SERVER */
#ifdef XGQ_SERVER
        struct xgq_ring *ring = &xgq->xq_cq;
#else
        struct xgq_ring *ring = &xgq->xq_sq;
#endif

        if (unlikely(!xgq_can_produce(xgq)))
                return -ENOSPC;
        *slot_addr = xgq_ring_slot_ptr_produced(ring);
        ring->xr_produced++;
        return 0;
}

int xgq_consume(struct xgq *xgq, u64 *slot_addr)
{
/* Host driver is XGQ_CLIENT and VMR is XGQ_SERVER */
#ifdef XGQ_SERVER
        struct xgq_ring *ring = &xgq->xq_sq;
#else
        struct xgq_ring *ring = &xgq->xq_cq;
#endif

        if (unlikely(!xgq_can_consume(xgq)))
                return -ENOENT;
        *slot_addr = xgq_ring_slot_ptr_consumed(ring);
        ring->xr_consumed++;

        return 0;
}

void xgq_notify_peer_produced(struct xgq *xgq)
{
/* Host driver is XGQ_CLIENT and VMR is XGQ_SERVER */
#ifdef XGQ_SERVER
        xgq_ring_write_produced(xgq->xq_io_hdl, &xgq->xq_cq);
#else
        xgq_ring_write_produced(xgq->xq_io_hdl, &xgq->xq_sq);
#endif

}

void xgq_notify_peer_consumed(struct xgq *xgq)
{
/* Host driver is XGQ_CLIENT and VMR is XGQ_SERVER */
#ifdef XGQ_SERVER
        xgq_ring_write_consumed(xgq->xq_io_hdl, &xgq->xq_sq);
#else
        xgq_ring_write_consumed(xgq->xq_io_hdl, &xgq->xq_cq);
#endif
}
