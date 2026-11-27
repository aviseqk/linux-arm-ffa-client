#include <asm-generic/errno.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/arm_ffa.h>
#include <linux/module.h>
#include <linux/uuid.h>
#include <linux/errno.h>
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/atomic.h>
#include <linux/bitmap.h>
#include <linux/device.h>
#include <linux/delay.h>


//#include "ffa_client_internal.h" 

/* matching the small test protocol implemented by the Secure Partition.
 * NOTE: this is a small application-level request/response protocol
 * on top of the FF-A Direct messaging for testing the 
 * Linux <-> SP Direct Messaging round-trip Test */
#define FFA_REF_REQUEST_MAGIC       0x4c4e5831  /* LNX1 */
#define FFA_REF_RESPONSE_MAGIC      0x53505231  /* SPR1 */

#define FFA_REF_OPCODE_XOR          1

#define FFA_REF_REQUEST_NONCE       0x1234abcd
#define FFA_REF_REQUEST_VALUE       0x11223344

#define FFA_REF_XOR_MASK            0xa5a5a5a5
#define FFA_REF_RESPONSE_TRAILER    0x53504f4e  /* SPON */

#define FFA_REF_STATUS_OK           0

/* UUID for ref-test-SP */
static const struct ffa_device_id ffa_ref_client_id_table[] = {
	{
		.uuid = UUID_INIT(
				0xf250793f,
				0xe540,
				0x097a,
				0xb9, 0x68, 0x83, 0xbd,
				0x7d, 0xa0, 0xbb, 0x4c
				),
	},
	{}
};

int ffa_direct_msg_test(struct ffa_device *ffa_dev)
{
	const struct ffa_msg_ops *msg_ops;
	struct ffa_send_direct_data msg = {0};
	int ret;

	if (!ffa_dev->ops || !ffa_dev->ops->msg_ops) {
		dev_err(&ffa_dev->dev,
				"FF-A messaging operations unavailable\n");
		return -EOPNOTSUPP;
	}

	msg_ops = ffa_dev->ops->msg_ops;

	if (!msg_ops->mode_32bit_set || !msg_ops->sync_send_receive) {
		dev_err(&ffa_dev->dev,
				"Required FF-A messaging operations unavailable\n");
		return -EOPNOTSUPP;
	}

	// make linux's native FF-A core choose 32 bit messaging convention
	msg_ops->mode_32bit_set(ffa_dev);
	
	dev_info(&ffa_dev->dev, "Using FF-A 32 bit Direct Messaging\n");

	// prepare the request payload
	msg.data0 = FFA_REF_REQUEST_MAGIC;
	msg.data1 = FFA_REF_OPCODE_XOR;
	msg.data2 = FFA_REF_REQUEST_NONCE;
	msg.data3 = FFA_REF_REQUEST_VALUE;
	msg.data4 = 0;

	dev_info(&ffa_dev->dev, "Sending Direct Request to SP\n");


	// the call for Linux<->SP communication, implemented by linux's native
	// FF-A core as sync_send_receive
	ret = msg_ops->sync_send_receive(ffa_dev, &msg);

	if (ret) {
		dev_err(&ffa_dev->dev,
				"FF-A Direct Messaging Failed: %d\n", ret);
		return ret;
	}

	dev_info(&ffa_dev->dev, "Received Direct response from SP\n");

	// validate the Direct response from SP
	if ((u32)msg.data0 != FFA_REF_RESPONSE_MAGIC) {
		dev_err(&ffa_dev->dev,
				"Incorrect response magic: 0x%08x\n",
				(u32)msg.data0);
		return -EPROTO;
	}

	if ((u32)msg.data1 != FFA_REF_STATUS_OK) {
		dev_err(&ffa_dev->dev,
				"SP returned protocol error status: %u\n",
				(u32)msg.data1);
		return -EPROTO;
	}

	if ((u32)msg.data2 != FFA_REF_REQUEST_NONCE) {
		dev_err(&ffa_dev->dev,
				"Nonce mismatch: 0x%08x\n",
				(u32)msg.data2);
		return -EPROTO;
	}

	if ((u32)msg.data3 !=(FFA_REF_REQUEST_VALUE ^ FFA_REF_XOR_MASK)) {
		dev_err(&ffa_dev->dev,
				"Incorrect transformed value: 0x%08x expected: 0x%08x\n",
				(u32)msg.data3,
				(FFA_REF_REQUEST_VALUE ^ FFA_REF_XOR_MASK));
		return -EPROTO;
	}

	if ((u32)msg.data4 != FFA_REF_RESPONSE_TRAILER) {
		dev_err(&ffa_dev->dev,
				"Incorrect Response Trailer: 0x%08x\n",
				(u32)msg.data4);
		return -EPROTO;
	}

	dev_info(&ffa_dev->dev, "All response fields validated\n");

	dev_info(&ffa_dev->dev,
			"Response: magic=0x%08x status=%u nonce=0x%08x value=0x%08x trailer=0x%08x\n",
			(u32)msg.data0,
             		(u32)msg.data1,
             		(u32)msg.data2,
             		(u32)msg.data3,
             		(u32)msg.data4);

	return 0;
}

#define FFA_REF2_REQUEST_MAGIC		0x4c4e5832ULL
#define FFA_REF2_OPCODE_XOR		0x1ULL
#define FFA_REF2_RESPONSE_MAGIC		0x53505232ULL
#define FFA_REF2_XOR_MASK		0xa5a5a5a5a5a5a5a5ULL
#define FFA_REF2_STATUS_OK		0x0ULL
#define FFA_REF2_SEQUENCE_NO		0x1ULL
int ffa_direct_msg2_test(struct ffa_device *ffa_dev)
{
	unsigned long request_pattern[14] = {
		FFA_REF2_REQUEST_MAGIC,    /* x4: Magic */
		FFA_REF2_OPCODE_XOR,	   /* x5: Command */
		FFA_REF2_SEQUENCE_NO,      /* x6: Sequence number */
		0x0123456789abcdefULL,     /* x7 */
		0xfedcba9876543210ULL,     /* x8 */
		0x8000000000000000ULL,     /* x9 */
		0x7fffffffffffffffULL,     /* x10 */
		0xffffffffffffffffULL,     /* x11 */
		0x0000000100000000ULL,     /* x12 */
		0xdeadbeefcafebabeULL,     /* x13 */
		0x0102030405060708ULL,     /* x14 */
		0x8877665544332211ULL,     /* x15 */
		0xaaaaaaaa55555555ULL,     /* x16 */
		0x00000000ffffffffULL,     /* x17 */
	};

	const struct ffa_msg_ops *msg_ops;
	struct ffa_send_direct_data2 msg = {0};
	int ret;
	
	msg_ops = ffa_dev->ops->msg_ops;

	if (!msg_ops|| !msg_ops->sync_send_receive2) {
		dev_err(&ffa_dev->dev,
				"Required FF-A messaging operations unavailable\n");
		return -EOPNOTSUPP;
	}

	for (unsigned int i = 0; i < 14; i++) {
		msg.data[i] = request_pattern[i];
	}

	dev_info(&ffa_dev->dev, "Sending Direct Request to SP\n");
	ret = msg_ops->sync_send_receive2(ffa_dev, &msg);
	if (ret) {
		dev_err(&ffa_dev->dev,
				"FF-A Direct Messaging v2 Failed: %d\n", ret);
		return ret;
	}	

	dev_info(&ffa_dev->dev, "Received Direct response from SP\n");

	if (msg.data[0] != FFA_REF2_RESPONSE_MAGIC)
		return -EPROTO;
	if (msg.data[1] != FFA_REF2_STATUS_OK)
		return -EPROTO;
	if (msg.data[2] != FFA_REF2_SEQUENCE_NO)
		return -EPROTO;

	for (unsigned int i = 3; i < 14; i++) {
		u64 expected = (u64)request_pattern[i] ^ FFA_REF2_XOR_MASK;

		if ((u64)msg.data[i] != expected) {
			dev_err(&ffa_dev->dev,
				"Payload mismatch: x%u: expected 0x%16llx got 0x%16llx\n",
				i + 4,
				(unsigned long long)expected,
				(unsigned long long)msg.data[i]);
			return -EPROTO;
		}
	}

	dev_info(&ffa_dev->dev, "All response fields validated\n");
	
	return 0;
}

struct ffa_ref_indirect_msg {
	u32 magic;
	u32 opcode;
	u32 sequence;
	u32 count;

	u64 values[4];
};

struct ffa_ref_indirect_ctx {
	struct completion response_ready;

	struct ffa_ref_indirect_msg response;

	bool registered;
	bool received;
};

/* framework Rx-buffer-full callback API */
static void ffa_ref_fwk_rx_callback( int notify_id, void *cb_data, void *buf)
{
	pr_info("ffa_ref_fwk_rx_callback: framework RX callback entered, notify_id=%d\n",notify_id);

	struct ffa_ref_indirect_ctx *ctx = cb_data;

	if (notify_id != 0)
		return;

	memcpy(&ctx->response, buf, sizeof(ctx->response));

	ctx->received = true;
	
	pr_info("ffa_ref_fwk_rx_callback(): response copied and validated: calling complete()\n");
	complete(&ctx->response_ready);
}

/* callback for linux scheduler to invoke when it learns SP needs scheduling via SRI */
static void ffa_ref_sched_recv_cb(u16 vcpu, bool is_per_vcpu, void *cb_data)
{
	struct ffa_device *ffa_dev = cb_data;

	dev_info(&ffa_dev->dev,
		"Schedule receiver callback: vcpu=%u per_vcpu=%d\n", vcpu, is_per_vcpu);

	// NOTE: because in callback registeration, we have ffa_dev as cb_data, maybe we can think 
	// of adding ffa_dev in ctx so that that could be passed on to the callbacks
	//struct ffa_ref_indirect_ctx *ctx = cb_data;
	
	int ret = ffa_dev->ops->cpu_ops->run(ffa_dev, vcpu);

	dev_info(&ffa_dev->dev,"FFA_RUN completed: ret=%d\n", ret);
}

#define FFA_REF_INDIRECT_REQUEST_MAGIC		0x494e4431U
#define FFA_REF_INDIRECT_RESPONSE_MAGIC		0x494e4432U
#define FFA_REF_INDIRECT_OPCODE_XOR		1U
#define FFA_REF_INDIRECT_STATUS_OK		0U

#define FFA_REF_INDIRECT_XOR_MASK		0xa5a5a5a5a5a5a5a5ULL

#define FFA_SP_INDIRECT_RESP_TIMEOUT		msecs_to_jiffies(5000)
int ffa_indirect_msg_test(struct ffa_device *ffa_dev)
{
	const struct ffa_msg_ops *msg_ops;
	const struct ffa_notifier_ops *notifier_ops;

	struct ffa_ref_indirect_ctx *ctx;
	struct ffa_ref_indirect_msg request = {
		.magic = FFA_REF_INDIRECT_REQUEST_MAGIC,
		.opcode = FFA_REF_INDIRECT_OPCODE_XOR,
		.sequence = 0x42,
		.count = 4,
		.values = {
			0x0123456789abcdefULL,
			0xfedcba9876543210ULL,
			0x8000000000000000ULL,
			0xdeadbeefcafebabeULL,
		},
	};

	int ret;
	
	if (!ffa_dev->ops || !ffa_dev->ops->msg_ops || !ffa_dev->ops->notifier_ops)
		return -EOPNOTSUPP;

	msg_ops = ffa_dev->ops->msg_ops;
	notifier_ops = ffa_dev->ops->notifier_ops;

	if (!msg_ops->indirect_send ||
		!notifier_ops->fwk_notify_request ||
		!notifier_ops->fwk_notify_relinquish) {
		dev_err(&ffa_dev->dev,
				"Required FF-A messaging operations unavailable\n");
		return -EOPNOTSUPP;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	init_completion(&ctx->response_ready);

	// register for the Rx-Buffer-Full framework notification
	ret = notifier_ops->fwk_notify_request(ffa_dev, 
			ffa_ref_fwk_rx_callback,
			ctx, 0);

	if (ret) {
		dev_err(&ffa_dev->dev, "Framework notification registration failed: %d\n", ret);
		kfree(ctx);
		return ret;
	}

	// TODO: implement this properly
	ret = notifier_ops->sched_recv_cb_register(ffa_dev,
			ffa_ref_sched_recv_cb, ffa_dev);

	if (ret) {
		dev_err(&ffa_dev->dev, "Failed to register scheduler callback: %d\n", ret);
		//kfree(ctx);
		return ret;
	}

	ctx->registered = true;
	ffa_dev_set_drvdata(ffa_dev, ctx);

	dev_info(&ffa_dev->dev, "Sending indirect FF-A request to SP\n");

	// call to do the Linux Tx-Buffer -> SP Rx-Buffer, and the FF-A core creates the parition-message header itself
	ret = msg_ops->indirect_send(ffa_dev, &request, sizeof(request));
	if (ret) {
		dev_err(&ffa_dev->dev,
				"FFA_MSG_SEND2 Failed: %d\n", ret);
		goto unregister;
	}
	

	/* INFO: FF-A Indirect messaging is asynchronous, so response by SP won't be immediate 
	 * we can wait for the SP's response using the Linux's Rx Buffer, till a timeout duration */

	if (!wait_for_completion_timeout(&ctx->response_ready, FFA_SP_INDIRECT_RESP_TIMEOUT)) {
		dev_err(&ffa_dev->dev,
				"Timed out waiting for indirect msg response\n");

		// NOTE: kept the context and callback registered so that a late response cannot access freed callback state
		return -ETIMEDOUT;
	}

	if (!ctx->received) {
		ret = -EPROTO;
		goto unregister;
	}

	dev_info(&ffa_dev->dev, "completion wait returned\n");

	/* reaching here in execution means a valid response was received, lets validate it */
	if (ctx->response.magic != FFA_REF_INDIRECT_RESPONSE_MAGIC ||
		ctx->response.opcode != FFA_REF_INDIRECT_STATUS_OK ||
		ctx->response.sequence != request.sequence ||
		ctx->response.count != request.count) {
		dev_err(&ffa_dev->dev, "Invalid Indirect Response Header\n");
		dev_info(&ffa_dev->dev,
			"magic: %u opcode: %u sequence: %u count: %u\n",
			ctx->response.magic, ctx->response.opcode,
			ctx->response.sequence, ctx->response.count);
		ret = -EPROTO;
		goto unregister;
	}

	for (unsigned int i = 0; i < 4; i++) {
		u64 expected = request.values[i] ^ FFA_REF_INDIRECT_XOR_MASK;

		if (ctx->response.values[i] != expected) {
			dev_err(&ffa_dev->dev,
					"Indirect payload mismatch at index %u: "
					"got 0x%016llx expected 0x%016llx\n",
					i,
					(unsigned long long)ctx->response.values[i],
					(unsigned long long)expected);
			ret = -EPROTO;
			goto unregister;
		}
	}

	dev_info(&ffa_dev->dev, "Indirect Request/Response fully validated\n");

	ret = 0;

unregister:
	notifier_ops->fwk_notify_relinquish(ffa_dev, 0);
	notifier_ops->sched_recv_cb_unregister(ffa_dev);

	ctx->registered = false;
	ffa_dev_set_drvdata(ffa_dev, NULL);

	kfree(ctx);

	return ret;
}

#define NOTIF_LINUX_TO_SP_ID		19U
#define NOTIF_LINUX_TO_SP_ID		19U
#define NOTIF_LINUX_REBIND_ID		25U
#define NOTIF_LINUX_UNBOUND_ID		24U

#define NOTIF_SP_TO_LINUX_ID		20U
#define NOTIF_SP_TO_LINUX_MULTI_A_ID	21U
#define NOTIF_SP_TO_LINUX_MULTI_B_ID	22U
#define NOTIF_SP_REBIND_ACK_ID		23U

#define FFA_REF_MAX_NOTIFICATIONS	64

#define FFA_REF_NOTIFICATION_TIMEOUT	msecs_to_jiffies(5000)
#define FFA_REF_NOTIFICATION_SETTLE	200

#define NOTIF_SP_RESPONSE_MASK	\
			(BIT_ULL(NOTIF_SP_TO_LINUX_ID) | \
			 BIT_ULL(NOTIF_SP_TO_LINUX_MULTI_A_ID) | \
			 BIT_ULL(NOTIF_SP_TO_LINUX_MULTI_B_ID))

struct ffa_ref_notification_ctx {
	struct ffa_device *ffa_dev;

	DECLARE_BITMAP(registered, FFA_REF_MAX_NOTIFICATIONS);
	DECLARE_BITMAP(received, FFA_REF_MAX_NOTIFICATIONS);
	
	/* this is a separate callback counter for each notification ID,
	 * * allowing us to verify that repeated SETs calls for a pending 
	 * * notification ID does not lead to duplicate callback delivery */
	atomic_t callback_count[FFA_REF_MAX_NOTIFICATIONS];

	wait_queue_head_t waitq;
};

/* Application Notification Callback */
static void sp_notification_cb(int notify_id, void *cb_data)
{
	struct ffa_ref_notification_ctx *ctx = cb_data;

	if (notify_id >= FFA_REF_MAX_NOTIFICATIONS) {
		dev_err(&ctx->ffa_dev->dev,
				"Callback received for invalid notification ID: %d\n", notify_id);
		return;
	}

	atomic_inc(&ctx->callback_count[notify_id]);

	set_bit(notify_id, ctx->received);

	wake_up_all(&ctx->waitq);

	dev_info(&ctx->ffa_dev->dev,
			"[NOTIFICATION_CALLBACK]: received ID: %d (count=%d)\n",
			notify_id, atomic_read(&ctx->callback_count[notify_id]));
}

/* to bind SP as sender to a single notification ID and register the callback */
static int ffa_ref_notification_register(struct ffa_ref_notification_ctx *ctx,
		const struct ffa_notifier_ops *ops, int notify_id)
{
	int ret;

	ret = ops->notify_request(ctx->ffa_dev, false, sp_notification_cb, ctx, notify_id);
	if (ret) {
		dev_err(&ctx->ffa_dev->dev,
				"notify_request for ID %d failed: %d\n", notify_id, ret);
		return ret;
	}

	set_bit(notify_id, ctx->registered);
	dev_info(&ctx->ffa_dev->dev,
			"Registered callback and bound SP as sender for ID %d\n", notify_id);

	return 0;
}

static void ffa_ref_notifications_count_zero(struct ffa_ref_notification_ctx *ctx)
{
	bitmap_zero(ctx->received, FFA_REF_MAX_NOTIFICATIONS);

	for (unsigned int i = 0; i < FFA_REF_MAX_NOTIFICATIONS; i++) {
		atomic_set(&ctx->callback_count[i], 0);
	}
}

/* function to check whether all requested notification IDs have reached their callbacks
 * NOTE: This is the condition check for the waitqueue, basically the event for test task on
 * of the waitqueue is waiting on to be true, that all required notification IDs have been received */
static bool ffa_ref_notification_mask_received(struct ffa_ref_notification_ctx *ctx, u64 mask)
{
	for (unsigned int i = 0; i < FFA_REF_MAX_NOTIFICATIONS; i++) {
		if ((mask & BIT_ULL(i)) && 
			!test_bit(i, ctx->received))
			return false;
	}
	return true;
}

static int ffa_ref_wait_for_notifications(struct ffa_ref_notification_ctx *ctx, u64 mask)
{
	long waited;

	waited = wait_event_timeout(ctx->waitq,
			ffa_ref_notification_mask_received(ctx, mask),
			FFA_REF_NOTIFICATION_TIMEOUT);

	return waited ? 0 : -ETIMEDOUT;
}

/* to verify that each requested notification ID has caused just one callback invocation */
static int ffa_ref_verify_single_delivery(struct ffa_ref_notification_ctx *ctx,
		const unsigned int *ids, size_t count)
{
	msleep(FFA_REF_NOTIFICATION_SETTLE);

	for(size_t i = 0; i < count; i++) {
		int callbacks;

		callbacks = atomic_read(&ctx->callback_count[ids[i]]);
		if (callbacks != 1) {
			dev_err(&ctx->ffa_dev->dev,
					"Notification ID %d callback count %d expected 1\n",
					ids[i], callbacks);
			return -EPROTO;
		}
	}
	return 0;
}

/* Cleanup Function - This function relenquishes every bound sender notification 
 * using `notify_relenquish`and unregisters the callback */
static void ffa_ref_notifications_cleanup(void *data)
{
	struct ffa_ref_notification_ctx *ctx = data;
	const struct ffa_notifier_ops *notifier_ops;
	unsigned long id;

	if (!ctx || !ctx->ffa_dev || !ctx->ffa_dev->ops || !ctx->ffa_dev->ops->notifier_ops)
		return;

	notifier_ops = ctx->ffa_dev->ops->notifier_ops;
	if (!notifier_ops->notify_relinquish)
		return;

	for_each_set_bit(id, ctx->registered, FFA_REF_MAX_NOTIFICATIONS) {
		int ret;

		ret = notifier_ops->notify_relinquish(ctx->ffa_dev, (int)id);
		if (ret) {
			dev_warn(&ctx->ffa_dev->dev,
					"Failed to relenquish notificatin ID: %lu\n", id);
		} else {
			clear_bit(id, ctx->registered);
			dev_info(&ctx->ffa_dev->dev,
					"Relenquished application notification ID: %lu\n", id);
		}
	}
}

static int ffa_ref_notification_complete_test(struct ffa_device *ffa_dev)
{
	const struct ffa_notifier_ops *notifier_ops;
	struct ffa_ref_notification_ctx *ctx;
	int ret;

	if (!ffa_dev->ops || !ffa_dev->ops->notifier_ops)
		return -EOPNOTSUPP;

	notifier_ops = ffa_dev->ops->notifier_ops;

	if (!notifier_ops->notify_send || !notifier_ops->notify_request || !notifier_ops->notify_relinquish)
		return -EOPNOTSUPP;

	ctx = devm_kzalloc(&ffa_dev->dev, sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->ffa_dev = ffa_dev;

	init_waitqueue_head(&ctx->waitq);

	for (unsigned int i = 0; i < FFA_REF_MAX_NOTIFICATIONS; i++)
		atomic_set(&ctx->callback_count[i], 0);

	ret = devm_add_action_or_reset(
			&ffa_dev->dev, ffa_ref_notifications_cleanup, ctx);
	if (ret)
		return ret;

	// Linux is the receiver for the IDs 20, 21, 22, 23
	static const int callback_ids[] = {
		NOTIF_SP_TO_LINUX_ID,
		NOTIF_SP_TO_LINUX_MULTI_A_ID,
		NOTIF_SP_TO_LINUX_MULTI_B_ID,
		NOTIF_SP_REBIND_ACK_ID,
	};

	// binding SP as the sender for the above IDs
	for (unsigned int i = 0; i < ARRAY_SIZE(callback_ids); i++) {
		ret = ffa_ref_notification_register(ctx, notifier_ops, callback_ids[i]);
		if (ret)
			return ret;
	}
	dev_info(&ffa_dev->dev, "[NOTIF TEST]: Callback Registration complete\n");

	/* Test 1: Linux sends ID 24 to the SP
	 * This is an invalid notification as SP never bounded this to Linux,
	 * hence this must be rejected */
	ret = notifier_ops->notify_send(ffa_dev, NOTIF_LINUX_UNBOUND_ID, false, 0);
	if (!ret) {
		dev_err(&ffa_dev->dev,
				"[NOTIF TEST]: unbound Linux -> SP ID 24 was unexpectedly accepted\n");
		return -EPROTO;
	}
	dev_info(&ffa_dev->dev,
			"[NOTIF TEST]: [PASS]: unbound Linux -> SP ID 24 was rejected(%d)\n", ret);
	

	/* Test 2: Linux sends ID 19 for the first time 
	 *
	 * in the testing sequence, SP after getting the first ID 19 signaled, it
	 * - attempts UNBIND while ID 19 is pending 
	 * - GETs ID 19
	 * - GETs again to verify the bitmap has been cleared
	 * - UNBINDs ID 19
	 * - tests invalid SET parameters
	 * - sends ID 20, 21, 22 to Linux as Multi notifs
	 *
	 *   So the final checking of this test, will be a mask of ID 20, 21, 22
	 *   */
	static const unsigned int response_ids[] = {
		NOTIF_SP_TO_LINUX_ID,
		NOTIF_SP_TO_LINUX_MULTI_A_ID,
		NOTIF_SP_TO_LINUX_MULTI_B_ID,
	};

	ffa_ref_notifications_count_zero(ctx);

	ret = notifier_ops->notify_send(ffa_dev, NOTIF_LINUX_TO_SP_ID, false, 0);
	if (ret) {
		dev_err(&ffa_dev->dev,
				"[NOTIF TEST] sending ID 19 failed: %d\n", ret);
		return ret;
	}

	// wait for all three SP -> Linux notification callbacks
	ret = ffa_ref_wait_for_notifications(ctx, NOTIF_SP_RESPONSE_MASK);
	if (ret) {
		dev_err(&ffa_dev->dev, "[NOTIF TEST] timed out waiting for IDs 20, 21 and 22: %d\n", ret);
		return ret;
	}

	ret = ffa_ref_verify_single_delivery(ctx, response_ids, ARRAY_SIZE(response_ids));
	if (ret)
		return ret;

	dev_info(&ffa_dev->dev,
			"[NOTIF TEST]: [PASS]: IDs 20,21,22 delivered once; repeated ID 20 SET also merged\n");


	/* Test 3: Linux tries to send ID 19 again,
	 * but the SP has unbound it already in last test */
	ret = notifier_ops->notify_send(ffa_dev, NOTIF_LINUX_TO_SP_ID, false, 0);
	if (!ret) {
		dev_err(&ffa_dev->dev,
				"[NOTIF TEST]: [FAIL]: ID 19 succeeded even after SP has unbound it; should have been rejected\n");
		return -EPROTO;
	}
	dev_info(&ffa_dev->dev, "[NOTIF TEST]: [PASS]: Linux -> SP ID 19 rejected after UNBIND: %d\n", ret);

	/* Test 4: Linux asks SP to bind ID 19 again
	 * using the ID 25 which is the rebind signal */
	ffa_ref_notifications_count_zero(ctx);

	ret = notifier_ops->notify_send(ffa_dev, NOTIF_LINUX_REBIND_ID, false, 0);
	if (ret) {
		dev_err(&ffa_dev->dev, "[NOTIF TEST] sending rebind control ID 25 failed: %d\n", ret);
		return ret;
	}

	ret = ffa_ref_wait_for_notifications(ctx, BIT_ULL(NOTIF_SP_REBIND_ACK_ID));
	if (ret) {
		dev_err(&ffa_dev->dev, "[NOTIF TEST] timed out waiting for ack ID 23: %d\n", ret);
		return ret;
	}

	{
		const unsigned int ack_id = NOTIF_SP_REBIND_ACK_ID;
		ret = ffa_ref_verify_single_delivery(ctx, &ack_id, 1);
	}
	if (ret)
		return ret;
	dev_info(&ffa_dev->dev,
			"[NOTIF TEST]: [PASS]: SP rebound ID 19 and acknowledged with ID 23\n");


	/* Test 5: Checking that signaling via ID 19 works just like earlier
	 * after it has been rebounded */
	ffa_ref_notifications_count_zero(ctx);

	ret = notifier_ops->notify_send(ffa_dev, NOTIF_LINUX_TO_SP_ID, false, 0);
	if (ret) {
		dev_err(&ffa_dev->dev, "[NOTIF TEST] ID 19 setting failed after SP rebind: %d\n", ret);
		return ret;
	}

	ret = ffa_ref_wait_for_notifications(ctx, NOTIF_SP_RESPONSE_MASK);
	if (ret) {
		dev_err(&ffa_dev->dev, "[NOTIF TEST] timed out waiting for post-rebound IDs (%d)\n", ret);
		return ret;
	}

	ret = ffa_ref_verify_single_delivery(ctx, response_ids, ARRAY_SIZE(response_ids));
	if (ret)
		return ret;

	dev_info(&ffa_dev->dev,
			"[NOTIF TEST]: [PASS]: ID 19 works after rebind, as IDs 20,21,22 were delivered once\n");


	dev_info(&ffa_dev->dev, "Notification Lifecycle tests PASSED\n");

	return 0;
}


static int ffa_ref_client_probe(struct ffa_device *ffa_dev)
{
	const struct ffa_notifier_ops *notifier_ops;
	int ret;

	dev_info(&ffa_dev->dev, "FF-A reference client probed\n");
	dev_info(&ffa_dev->dev,
			"Discovered our SP, endpoint ID=0x%04x\n", (u16)ffa_dev->vm_id);

	
	// check that the SP supports direct requests reception
	if (!ffa_partition_supports_direct_recv(ffa_dev)) {
		dev_err(&ffa_dev->dev,
				"Partition does not advertise Direct Request Reception\n");
		return -EOPNOTSUPP;
	}
	
	dev_info(&ffa_dev->dev, "[TEST1: Direct Messaging]\n");
	ret = ffa_direct_msg_test(ffa_dev); 
	if (ret != 0) {
		dev_err(&ffa_dev->dev,
				"Linux <-> SP direct messaging test FAILED\n");
		return -1;
	}
	
	dev_info(&ffa_dev->dev,
			"Linux <-> SP direct messaging test PASSED\n");

	// reset the `mode_32bit` mode and then check that SP supports direct requests v2
	// TODO: do not do this manually, tampering with kernel's internal values,
	// rather do the v2 test first and then set mode32_bit via the exposed interface
	ffa_dev->mode_32bit = false;
	if (!ffa_partition_supports_direct_req2_recv(ffa_dev)) {
		dev_err(&ffa_dev->dev,
				"Partition does not advertise Direct Request v2 Reception\n");
		return -EOPNOTSUPP;
	}

	dev_info(&ffa_dev->dev, "[TEST2: Direct Messaging v2]\n");
	ret = ffa_direct_msg2_test(ffa_dev); 
	if (ret != 0) {
		dev_err(&ffa_dev->dev,
				"Linux <-> SP direct messaging v2 test FAILED\n");
		return -1;
	}
	
	dev_info(&ffa_dev->dev,
			"Linux <-> SP direct messaging v2 test PASSED\n");
	
	if (!ffa_partition_supports_indirect_msg(ffa_dev)) {
		dev_err(&ffa_dev->dev,
				"Partition does not advertise Indirect Messaging\n");
		return -EOPNOTSUPP;
	}

	/* INFO: need to register the SRI i.e. the scheduler callback before the notification test */
	notifier_ops = ffa_dev->ops->notifier_ops;

	if (!notifier_ops->sched_recv_cb_register || 
		!notifier_ops->sched_recv_cb_unregister ||
		!ffa_dev->ops->cpu_ops ||
		!ffa_dev->ops->cpu_ops->run) {

		dev_err(&ffa_dev->dev, "Required scheduler operations unavailable\n");
		return -EOPNOTSUPP;
	}

	ret = notifier_ops->sched_recv_cb_register(ffa_dev, ffa_ref_sched_recv_cb, ffa_dev);
	if (ret) {
		dev_err(&ffa_dev->dev, "Failed to register scheduler reciever callback: %d\n", ret);
		return ret;
	}
	dev_info(&ffa_dev->dev, "Scheduler Receiver Callback registered for notification tests\n");

	// BUG: notification test from here REMOVE THIS FROM HERE
	dev_info(&ffa_dev->dev, "[TEST]: FF-A Notification Lifecycle Test\n");
	ret = ffa_ref_notification_complete_test(ffa_dev);
	
	/* unregister Scheduler reciever callbacks whether notification test passed or failed,
	 * as for later indirect msg test, it is re-registered again */
	{
		int unreg_ret;

		unreg_ret = notifier_ops->sched_recv_cb_unregister(ffa_dev);
		if (unreg_ret) {
			dev_err(&ffa_dev->dev, "Failed to unregister the SRI callbacks: %d\n", ret);
			
			if (!ret)
				ret = unreg_ret;
		}
	}

	if (ret) {
		dev_err(&ffa_dev->dev, "FF-A Notification Lifecycle tests FAILED: %d\n",ret);
		return ret;
	} else {
		dev_info(&ffa_dev->dev,"[TEST]: FF-A Notification Lifecycle tests PASSED\n");
	}
	
	dev_info(&ffa_dev->dev, "[TEST3]: Indirect Messaging\n");
	ret = ffa_indirect_msg_test(ffa_dev);
	if (ret == -ETIMEDOUT) {
		dev_err(&ffa_dev->dev,
				"Indirect messaging timed out; "
				"callback remains registered for cleanup\n");
	} else if (ret) {
		dev_err(&ffa_dev->dev,
				"Linux <-> SP indirect messaging test FAILED\n");
		return ret;
	} else {
		dev_info(&ffa_dev->dev,
				"Linux <-> SP indirect messaging test PASSED\n");
	}

	return 0;

}

static void ffa_ref_client_remove(struct ffa_device *ffa_dev)
{
	struct ffa_ref_indirect_ctx *ctx = ffa_dev_get_drvdata(ffa_dev);

	if (ctx) {
		if (ctx->registered &&
			ffa_dev->ops &&
			ffa_dev->ops->notifier_ops &&
			ffa_dev->ops->notifier_ops->fwk_notify_relinquish) {
			
			ffa_dev->ops->notifier_ops->fwk_notify_relinquish(ffa_dev, 0);
		}
		ffa_dev_set_drvdata(ffa_dev, NULL);
		kfree(ctx);
	}

	// TODO: add a flag like registered in ctx for the sched recv callback being registered too
	if (ffa_dev->ops && ffa_dev->ops->notifier_ops &&
			ffa_dev->ops->notifier_ops->sched_recv_cb_unregister) {
		ffa_dev->ops->notifier_ops->sched_recv_cb_unregister(ffa_dev);
	}

	dev_info(&ffa_dev->dev, "FF-A reference client removed\n");
}

// TODO: Linux Arm FFA Driver gives a notifier_ops registration 
// handle in this struct, use that instead of individual callback registrations
static struct ffa_driver ffa_ref_client_driver = {
	.name = "ffa_ref_client",
	.probe = ffa_ref_client_probe,
	.remove = ffa_ref_client_remove,
	.id_table = ffa_ref_client_id_table,
};

module_ffa_driver(ffa_ref_client_driver)

MODULE_AUTHOR("Abhishek Kumar");
MODULE_DESCRIPTION("Linux Client Driver for our ref FFA SP");
MODULE_LICENSE("GPL v2");
