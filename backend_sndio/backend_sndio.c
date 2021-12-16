/*-
 * Copyright (c) 2021 Tim Creech <tcreech@tcreech.com>. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <err.h>
#include <stdlib.h>
#include <string.h>

#include <sys/queue.h>
#include <sys/soundcard.h>
#include <sndio.h>

#include "../virtual_int.h"
#include "../virtual_backend.h"

struct sio_ctx {
	struct sio_hdl* hdl;
	long long realpos;
	long long writepos;
};

static struct sio_ctx*
get_sio_ctx(struct voss_backend *pbe)
{
	if (pbe)
		return (pbe->arg);

	return (NULL);
}

static struct sio_hdl*
get_sio_hdl(struct voss_backend *pbe)
{
	struct sio_ctx* ctx = get_sio_ctx(pbe);

	if (ctx)
		return (ctx->hdl);

	return (NULL);
}


static void
sndio_close(struct voss_backend *pbe)
{
	if (!pbe)
		return;

    if (get_sio_hdl(pbe))
        sio_close(get_sio_hdl(pbe));

	if (pbe->arg)
		free(pbe->arg);
}

static void
sndio_onmove_cb(void* addr, int delta)
{
	struct voss_backend *pbe = addr;
	/* Convert delta from frames to bytes using params assumed below */
	get_sio_ctx(pbe)->realpos += (delta * /*bps=*/2 * /*pchan=*/2);
}

static int sndio_get_signedness(int *fmt)
{
	int s_fmt = *fmt & (VPREFERRED_SLE_AFMT | VPREFERRED_SBE_AFMT);
	if (s_fmt) {
		*fmt = s_fmt;
		return (1);
	}
	*fmt = *fmt & (VPREFERRED_ULE_AFMT | VPREFERRED_UBE_AFMT);
	return (0);
}

static int sndio_get_endianness_is_le(int *fmt)
{
	int le_fmt = *fmt & (VPREFERRED_SLE_AFMT | VPREFERRED_ULE_AFMT);
	if (le_fmt) {
		*fmt = le_fmt;
		return (1);
	}
	*fmt = *fmt & (VPREFERRED_SBE_AFMT | VPREFERRED_UBE_AFMT);
	return (0);
}

static int sndio_get_bits(int *fmt)
{
	if (*fmt & (AFMT_S16_LE | AFMT_U16_LE | AFMT_S16_BE | AFMT_U16_BE)) {
		return (16);
	}
	if (*fmt & (AFMT_S24_LE | AFMT_U24_LE | AFMT_S24_BE | AFMT_U24_BE)) {
		return (24);
	}
	if (*fmt & (AFMT_S32_LE | AFMT_U32_LE | AFMT_S32_BE | AFMT_U32_BE)) {
		return (32);
	}
	if (*fmt & (AFMT_S8 | AFMT_U8)) {
		return (8);
	}
	return (-1);
}

static int
sndio_open(struct voss_backend *pbe, const char *devname,
    int samplerate, int bufsize, int *pchannels, int *pformat)
{
    const char *sndio_name = devname + strlen("/dev/sndio/");

	int sig = sndio_get_signedness(pformat);
	int le  = sndio_get_endianness_is_le(pformat);
	int bits = sndio_get_bits(pformat);

	if (bits == -1) {
		warn("unsupported format precision");
		return (-1);
	}

    struct sio_hdl* hdl =
        sio_open(sndio_name, SIO_PLAY, 0);
    if (hdl == 0) {
        warn("sndio: failed to open device");
        return (-1);
    }

    struct sio_par par;
    sio_initpar(&par);
	par.pchan = *pchannels;
	par.sig = sig;
	par.bits = bits;
	par.bps = SIO_BPS(bits);
	par.le = le;
	par.rate = samplerate;
	par.appbufsz = bufsize;
	par.xrun = SIO_SYNC;
	if (!sio_setpar(hdl, &par))
		errx(1, "internal error, sio_setpar() failed");
	if (!sio_getpar(hdl, &par))
		errx(1, "internal error, sio_getpar() failed");
	if (par.pchan != *pchannels)
		errx(1, "couldn't set number of channels");
	if (par.sig != sig || par.bits != bits || par.le != le)
		errx(1, "couldn't set format");
	if (par.bits != bits)
		errx(1, "couldn't set precision");
	if (par.rate < samplerate * 995 / 1000 ||
			par.rate > samplerate * 1005 / 1000)
		errx(1, "couldn't set rate");
	if (par.xrun != SIO_SYNC)
		errx(1, "couldn't set xun policy");

	/* Save the device handle in a context struct */
	struct sio_ctx* ctx = malloc(sizeof(struct sio_ctx));
	memset(ctx, 0, sizeof(struct sio_ctx));
	ctx->hdl= hdl;
	pbe->arg = ctx;

	/* Set up a callback to help compute delay */
	sio_onmove(hdl, sndio_onmove_cb, pbe);

	/* Start the device.*/
	if (!sio_start(hdl))
		errx(1, "couldn't start device");

	return (0);
}

static int
sndio_play_transfer(struct voss_backend *pbe, void *ptr, int len)
{
    size_t r = sio_write(get_sio_hdl(pbe), ptr, len);

	if (r >= 0) {
		get_sio_ctx(pbe)->writepos += r;
	}

    return (r);
}

static void
sndio_delay(struct voss_backend *pbe, int *pdelay)
{
	if (voss_has_synchronization == 0) {
		*pdelay = -1;
		return;
	}

	int delay = get_sio_ctx(pbe)->writepos - get_sio_ctx(pbe)->realpos;
	*pdelay = delay;

    /* We've computed a delay in bytes, but it may be too large to be handled
     * correctly by the main loop in virtual_oss_process. As a result, we don't
     * use it for now. */
	*pdelay = -1;
}

struct voss_backend voss_backend_sndio_play = {
	.open = sndio_open,
	.close = sndio_close,
	.transfer = sndio_play_transfer,
	.delay = sndio_delay,
};
