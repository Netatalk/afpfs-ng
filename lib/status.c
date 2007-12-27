#include <string.h>
#include <stdio.h>
#include "dsi.h"
#include "afp.h"

int afp_status_header(char * text, int * len) 
{
	int pos;
	memset(text,0,*len);

	pos=snprintf(text,*len,"AFPFS Version: %s\n"
		"UAMs compiled in: %s\n",
		AFPFS_VERSION,
		get_uam_names_list());
	*len-=pos;
	if (*len==0) return -1;
	return pos;
}

int afp_status_server(struct afp_server * s, char * text, int * len) 
{
	int j;
	struct afp_volume *v;
	char signature_string[AFP_SIGNATURE_LEN*2+1];
	int pos=0;

	memset(text,0,*len);

	if (s==NULL) {
		pos+=snprintf(text+pos,*len-pos,
			"Not connected to any servers\n");
		goto out;
	}
		
	for (j=0;j<AFP_SIGNATURE_LEN;j++)
		sprintf(signature_string+(j*2),"%02x",
			(unsigned int) ((char) s->signature[j]));
	
	pos+=snprintf(text+pos,*len-pos,
		"Server %s\n"
		"    connection: %s:%d %s\n"
		"    AFP version: %s\n"
		"    using UAM: %s\n"
		"    login message: %s\n"
		"    type: %s\n"
		"    signature: %s\n"
		"    transmit delay: %ums\n"
		"    quantums: %u(tx) %u(rx)\n"
		"    last request id: %d in queue: %llu\n"
		"    transfer: %llu(rx) %llu(tx)\n"
		"    runt packets: %llu\n",
	s->server_name_precomposed,
	inet_ntoa(s->address.sin_addr),ntohs(s->address.sin_port),
		(s->connect_state==SERVER_STATE_DISCONNECTED ? 
		"Disconnected" : "(active)"),
	s->using_version->av_name,
	uam_bitmap_to_string(s->using_uam),
	s->loginmesg,
	s->machine_type, signature_string,
	s->tx_delay,
	s->tx_quantum, s->rx_quantum,
	s->lastrequestid,s->stats.requests_pending,
	s->stats.rx_bytes,s->stats.tx_bytes,
	s->stats.runt_packets);

	if (*len==0) goto out;


	{
		struct dsi_request * r;
		for (r=s->command_requests;r;r=r->next) 
		pos+=snprintf(text+pos,*len-pos,
		"        outstanding packet command: %d: %d\n",
		r->requestid,r->subcommand);
	}
				
	for (j=0;j<s->num_volumes;j++) {
		v=&s->volumes[j];
		pos+=snprintf(text+pos,*len-pos,
		"    Volume %s, id %d, attribs 0x%x mounted: %s\n",
		v->volume_name_printable,v->volid,
		v->attributes,
		(v->mounted==AFP_VOLUME_MOUNTED) ? v->mountpoint:"No");

		if (v->mounted==AFP_VOLUME_MOUNTED) 
			pos+=snprintf(text+pos,*len-pos,
			"        did cache stats: %llu miss, %llu hit, %llu expired, %llu force removal\n        uid/gid mapping: %s (%d/%d)\n",
			v->did_cache_stats.misses, v->did_cache_stats.hits,
			v->did_cache_stats.expired, 
			v->did_cache_stats.force_removed,
			get_mapping_name(v),
			s->server_uid,s->server_gid);
		pos+=snprintf(text+pos,*len-pos,"\n");
	}

out:
	*len-=pos;
	return pos;

}
