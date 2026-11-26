#include <asm-generic/errno.h>
#include <linux/kernel.h>
#include <linux/arm_ffa.h>
#include <linux/module.h>
#include <linux/uuid.h>
#include <linux/errno.h>
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/slab.h>


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
#define NOTIF_SP_TO_LINUX_ID		20U

static void sp_notification_cb(int notify_id, void *cb_data)
{
	struct ffa_device *ffa_dev = cb_data;

	dev_info(&ffa_dev->dev,
			"[NOTIFICATION_CALLBACK]: Linux ran callback for notification %d\n", notify_id);
	
	if (notify_id != NOTIF_SP_TO_LINUX_ID)
		return;
}

int bind_ffa_notification_for_test(struct ffa_device *ffa_dev)
{
	const struct ffa_notifier_ops *notifier_ops;
	int ret;

	if (!ffa_dev->ops || !ffa_dev->ops->msg_ops || !ffa_dev->ops->notifier_ops)
		return -EOPNOTSUPP;

	notifier_ops = ffa_dev->ops->notifier_ops;

	ret = notifier_ops->notify_request(ffa_dev,
			false, sp_notification_cb,
			ffa_dev, NOTIF_SP_TO_LINUX_ID);

	if (ret)
		return ret;
	return 0;
}

int notify_sp_test(struct ffa_device *ffa_dev)
{
	dev_info(&ffa_dev->dev, "notify_sp_test called()\n");
	int ret;

	ret = ffa_dev->ops->notifier_ops->notify_send(ffa_dev, NOTIF_LINUX_TO_SP_ID, false, 0);
	if (ret)
		dev_err(&ffa_dev->dev, "Failed to notify SP \n");
	return ret;
	dev_info(&ffa_dev->dev, "SP was notified with ID: %d\n", NOTIF_LINUX_TO_SP_ID);
}

static int ffa_ref_client_probe(struct ffa_device *ffa_dev)
{
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

	// BUG: notification test from here REMOVE THIS FROM HERE
	ret = bind_ffa_notification_for_test(ffa_dev);
	if (ret) {
		dev_err(&ffa_dev->dev, "Linux unable to bind the notification %d to the SP\n", NOTIF_SP_TO_LINUX_ID);
		return ret;
	} else {
		dev_info(&ffa_dev->dev,
				"Linux bound Notification %d to the SP properly, now ringing the notification\n", NOTIF_SP_TO_LINUX_ID);
	}
	
	/* ringing the notification to the SP */
	dev_info(&ffa_dev->dev, "[TEST]: Notification Ringing\n");
	ret = notify_sp_test(ffa_dev);
	if (ret)
		dev_err(&ffa_dev->dev, "Unable to ring Notification %d to the SP\n", NOTIF_LINUX_TO_SP_ID);
	else 
		dev_info(&ffa_dev->dev, "Notification %d ringed to SP properly\n", NOTIF_LINUX_TO_SP_ID);


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
