#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_ERSPAN

#include "ndpi_api.h"
#include "ndpi_private.h"


static void ndpi_int_earspan_add_connection(struct ndpi_detection_module_struct *const ndpi_struct,
                                            struct ndpi_flow_struct *const flow)
{
    NDPI_LOG_INFO(ndpi_struct, "found erspan\n");
    ndpi_set_detected_protocol(ndpi_struct, flow,
                               NDPI_PROTOCOL_ERSPAN,
                               NDPI_PROTOCOL_UNKNOWN,
                               NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_erspan(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
    struct ndpi_packet_struct *packet = &ndpi_struct->packet;

    NDPI_LOG_DBG(ndpi_struct, "Search earspan\n");


    if (packet->iph)
    { 
        if (packet->iph->protocol == IPPROTO_GRE || packet->payload_packet_len == 58)
        {
            // Adding EARSPAN to the known protocols
            ndpi_int_earspan_add_connection(ndpi_struct, flow);
            
        }

    }
    
}
void init_erspan_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
    ndpi_set_bitmask_protocol_detection("EARSPAN", ndpi_struct, *id,
                                        NDPI_PROTOCOL_ERSPAN,
                                        ndpi_search_erspan,
                                        NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                                        SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                        ADD_TO_DETECTION_BITMASK);

    *id += 1;
}