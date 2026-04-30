#define AF_ALG 38
#define EBADMSG 74
#define MSG_SPLICE_PAGES 0x8000000

struct page {
  unsigned char bytes[4096];
  int dirty;
};

struct pipe_buffer {
  struct page *page;
};

struct scatterlist {
  struct page *page;
  unsigned int offset;
  unsigned int length;
  struct scatterlist *next;
};

struct aead_request {
  struct scatterlist *src;
  struct scatterlist *dst;
  unsigned int assoclen;
  unsigned int cryptlen;
  unsigned int authsize;
};

struct algif_aead_req {
  struct aead_request aead_req;
  struct scatterlist tx_sgl;
  struct scatterlist rx_sgl;
  struct scatterlist tag_sgl;
};

static struct page *sg_page(struct scatterlist *sg) {
  return sg->page;
}

static void sg_chain(struct scatterlist *head, int nents, struct scatterlist *tail) {
  (void)nents;
  head->next = tail;
}

static void aead_request_set_crypt(
  struct aead_request *req,
  struct scatterlist *src,
  struct scatterlist *dst,
  unsigned int cryptlen,
  int iv
) {
  (void)cryptlen;
  (void)iv;
  req->src = src;
  req->dst = dst;
}

static void scatterwalk_map_and_copy(
  unsigned int *value,
  struct scatterlist *sg,
  unsigned int offset,
  unsigned int len,
  int out
) {
  struct scatterlist *cursor = sg;
  while (cursor && offset >= cursor->length) {
    offset -= cursor->length;
    cursor = cursor->next;
  }
  if (!out || !cursor || !cursor->page || len != 4) {
    return;
  }
  cursor->page->bytes[cursor->offset + offset + 0] = (unsigned char)(*value >> 0);
  cursor->page->bytes[cursor->offset + offset + 1] = (unsigned char)(*value >> 8);
  cursor->page->bytes[cursor->offset + offset + 2] = (unsigned char)(*value >> 16);
  cursor->page->bytes[cursor->offset + offset + 3] = (unsigned char)(*value >> 24);
  cursor->page->dirty = 1;
}

static int authencesn_decrypt_tail(
  struct aead_request *req,
  unsigned int seqno_lo,
  int tag_ok
) {
  scatterwalk_map_and_copy(&seqno_lo, req->dst, req->assoclen + req->cryptlen, 4, 1);
  if (!tag_ok) {
    scatterwalk_map_and_copy(&seqno_lo, req->src, 4, 4, 1);
    return -EBADMSG;
  }
  return 0;
}

int algif_aead_recvmsg_splice(
  struct algif_aead_req *areq,
  struct page *page_cache_page,
  struct page *recv_page,
  unsigned int target_offset,
  unsigned int seqno_lo
) {
  int family = AF_ALG;
  unsigned int used = areq->aead_req.assoclen + areq->aead_req.cryptlen;
  struct pipe_buffer pipe = { .page = page_cache_page };
  struct scatterlist page_cache_sg = { .page = pipe.page, .offset = target_offset, .length = 4096 };

  areq->tx_sgl.page = sg_page(&page_cache_sg);
  areq->tx_sgl.offset = target_offset;
  areq->tx_sgl.length = areq->aead_req.authsize;
  areq->rx_sgl.page = recv_page;
  areq->rx_sgl.offset = 0;
  areq->rx_sgl.length = used;
  areq->tag_sgl.page = pipe.page;
  areq->tag_sgl.offset = target_offset;
  areq->tag_sgl.length = areq->aead_req.authsize;

  if (family == AF_ALG) {
    sg_chain(&areq->rx_sgl, 1, &areq->tag_sgl);
  }

  areq->aead_req.dst = &areq->rx_sgl;
  areq->aead_req.src = areq->aead_req.dst;
  if (areq->aead_req.src == areq->aead_req.dst) {
    aead_request_set_crypt(&areq->aead_req, &areq->rx_sgl, &areq->rx_sgl, used, 0);
  }

  return authencesn_decrypt_tail(&areq->aead_req, seqno_lo, 0);
}

int splice_page_cache_to_algif(void) {
  return splice(0, 0, 1, 0, 4096, MSG_SPLICE_PAGES);
}
