/*
 * Copyright (C) 2012-2013 NEC Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/ethtool.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "ether_device.h"
#include "mutex.h"


static const size_t MAX_L2_HEADER_LENGTH = 32;


static uint32_t
make_current_ofp_port_features( uint32_t speed, uint8_t duplex, uint8_t port, uint8_t autoneg,
                                uint32_t rx_pause, uint32_t tx_pause ) {
  uint32_t ofp_features = 0;

  if ( ( speed == SPEED_10 ) && ( duplex == DUPLEX_HALF ) ) {
    ofp_features |= OFPPF_10MB_HD;
  }
  if ( ( speed == SPEED_10 ) && ( duplex == DUPLEX_FULL ) ) {
    ofp_features |= OFPPF_10MB_FD;
  }
  if ( ( speed == SPEED_100 ) && ( duplex == DUPLEX_HALF ) ) {
    ofp_features |= OFPPF_100MB_HD;
  }
  if ( ( speed == SPEED_100 ) && ( duplex == DUPLEX_FULL ) ) {
    ofp_features |= OFPPF_100MB_FD;
  }
  if ( ( speed == SPEED_1000 ) && ( duplex == DUPLEX_HALF ) ) {
    ofp_features |= OFPPF_1GB_HD;
  }
  if ( ( speed == SPEED_1000 ) && ( duplex == DUPLEX_FULL ) ) {
    ofp_features |= OFPPF_1GB_FD;
  }
  if ( speed == SPEED_10000 ) {
    ofp_features |= OFPPF_10GB_FD;
  }
  if ( ( port == PORT_TP ) || ( port == PORT_AUI ) || ( port == PORT_BNC ) ) {
    ofp_features |= OFPPF_COPPER;
  }
  if ( port == PORT_FIBRE ) {
    ofp_features |= OFPPF_FIBER;
  }
  if ( autoneg == AUTONEG_ENABLE ) {
    ofp_features |= OFPPF_AUTONEG;
  }
  if ( rx_pause & tx_pause ) {
    ofp_features |= OFPPF_PAUSE;
  } else if ( rx_pause | tx_pause ) {
    ofp_features |= OFPPF_PAUSE_ASYM;
  }

  return ofp_features;
}


static uint32_t
make_supported_ofp_port_features( uint32_t features ) {
  uint32_t ofp_features = 0;

  if ( features & SUPPORTED_10baseT_Half ) {
    ofp_features |= OFPPF_10MB_HD;
  }
  if ( features & SUPPORTED_10baseT_Full ) {
    ofp_features |= OFPPF_10MB_FD;
  }
  if ( features & SUPPORTED_100baseT_Half ) {
    ofp_features |= OFPPF_100MB_HD;
  }
  if ( features & SUPPORTED_100baseT_Full ) {
    ofp_features |= OFPPF_100MB_FD;
  }
  if ( features & SUPPORTED_1000baseT_Half ) {
    ofp_features |= OFPPF_1GB_HD;
  }
  if ( features & ( SUPPORTED_1000baseT_Full | SUPPORTED_1000baseKX_Full ) ) {
    ofp_features |= OFPPF_1GB_FD;
  }
  if ( features & ( SUPPORTED_10000baseT_Full | SUPPORTED_10000baseKX4_Full | SUPPORTED_10000baseKR_Full ) ) {
    ofp_features |= OFPPF_10GB_FD;
  }
  if ( features & ( SUPPORTED_TP | SUPPORTED_AUI | SUPPORTED_BNC ) ) {
    ofp_features |= OFPPF_COPPER;
  }
  if ( features & SUPPORTED_FIBRE ) {
    ofp_features |= OFPPF_FIBER;
  }
  if ( features & SUPPORTED_Autoneg ) {
    ofp_features |= OFPPF_AUTONEG;
  }
  if ( features & SUPPORTED_Pause ) {
    ofp_features |= OFPPF_PAUSE;
  }
  if ( features & SUPPORTED_Asym_Pause ) {
    ofp_features |= OFPPF_PAUSE_ASYM;
  }

  return ofp_features;
}


bool
update_device_status( ether_device *device ) {
  assert( device != NULL );
  assert( strlen( device->name ) > 0 );

  int fd = socket( PF_INET, SOCK_DGRAM, 0 );
  if ( fd < 0 ) {
    char error_string[ ERROR_STRING_SIZE ];
    error( "Failed to open a socket ( ret = %d, errno = %s [%d] ).",
           fd, safe_strerror_r( errno, error_string, sizeof( error_string ) ), errno );
    return false;
  }

  struct ifreq ifr;
  memset( &ifr, 0, sizeof( ifr ) );
  strncpy( ifr.ifr_name, device->name, IFNAMSIZ );
  ifr.ifr_name[ IFNAMSIZ - 1 ] = '\0';

  struct ethtool_value ev;
  memset( &ev, 0, sizeof( struct ethtool_value ) );
  ev.cmd = ETHTOOL_GLINK;
  ifr.ifr_data = ( char * ) &ev;
  int ret = ioctl( fd, SIOCETHTOOL, &ifr );
  if ( ret == -1 ) {
    char error_string[ ERROR_STRING_SIZE ];
    error( "Failed to retrieve link status of %s ( ret = %d, error = %s [%d] ).",
           device->name, ret, safe_strerror_r( errno, error_string, sizeof( error_string ) ), errno );
    warn( "Assuming link is up ( device = %s ).", device->name );
    device->status.up = true;
  } else {
    if ( ev.data > 0 ) {
      device->status.up = true;
    } else {
      device->status.up = false;
    }
  }

  struct ethtool_cmd ec;
  memset( &ec, 0, sizeof( struct ethtool_cmd ) );
  if ( device->status.can_retrieve_link_status ) {
    ec.cmd = ETHTOOL_GSET;
    ifr.ifr_data = ( char * ) &ec;
    ret = ioctl( fd, SIOCETHTOOL, &ifr );
    if ( ret == -1 ) {
      char error_string[ ERROR_STRING_SIZE ];
      warn( "Failed to retrieve statuses of %s ( ret = %d, error = %s [%d] ).",
            device->name, ret, safe_strerror_r( errno, error_string, sizeof( error_string ) ), errno );
      warn( "Assuming 100Mbps/Full Duplex/Twisted Pair link ( device = %s ).", device->name );
      device->status.can_retrieve_link_status = false;
    }
  }
  if ( !device->status.can_retrieve_link_status ) {
    ethtool_cmd_speed_set( &ec, SPEED_100 );
    ec.duplex = DUPLEX_FULL;
    ec.port = PORT_TP;
    ec.advertising = ADVERTISED_100baseT_Full | ADVERTISED_TP;
    ec.supported = SUPPORTED_100baseT_Full | SUPPORTED_TP;
  }

  struct ethtool_pauseparam ep;
  memset( &ep, 0, sizeof( struct ethtool_pauseparam ) );
  if ( device->status.can_retrieve_pause ) {
    ep.cmd = ETHTOOL_GPAUSEPARAM;
    ifr.ifr_data = ( char * ) &ep;
    ret = ioctl( fd, SIOCETHTOOL, &ifr );
    if ( ret == -1 ) {
      char error_string[ ERROR_STRING_SIZE ];
      warn( "Failed to retrieve pause parameters of %s ( ret = %d, error = %s [%d] ).",
            device->name, ret, safe_strerror_r( errno, error_string, sizeof( error_string ) ), errno );
      warn( "Assuming pause is disabled ( device = %s ).", device->name );
      device->status.can_retrieve_pause = false;
    }
  }

  close( fd );

  device->status.curr = make_current_ofp_port_features( ethtool_cmd_speed( &ec ), ec.duplex, ec.port,
                                                        ec.autoneg, ep.rx_pause, ep.tx_pause );
  device->status.advertised = make_supported_ofp_port_features( ec.advertising );
  device->status.supported = make_supported_ofp_port_features( ec.supported );
  device->status.peer = device->status.curr; // FIMXE: how to know the correct value?
  device->status.curr_speed = 0; // Since we set curr flags, this field might be meaningless.
  device->status.max_speed = 0; // Since we set supported flags, this field might be meaningless.

  return true;
}


bool
update_device_stats( ether_device *device ) {
  assert( device != NULL );
  assert( strlen( device->name ) > 0 );

  FILE *fh = fopen( "/proc/net/dev", "r" );
  if ( fh == NULL ) {
    error( "Failed to open /proc/net/dev." );
    return false;
  }

  bool found = false;
  while ( 1 ) {
    char buf[ 256 ];
    char *line = fgets( buf, sizeof( buf ), fh );
    if ( line == NULL ) {
      break;
    }
    char *head = strstr( line, device->name );
    if ( head == NULL ) {
      continue;
    }

    head = head + strlen( device->name ) + 1; // skip "  eth0:"
    uint64_t trash;
    int ret = sscanf( head, "%" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64
                      " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64
                      " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64,
                      &device->stats.rx_bytes, &device->stats.rx_packets, &device->stats.rx_errors,
                      &device->stats.rx_dropped, &device->stats.rx_over_err, &device->stats.rx_frame_err,
                      &trash, &trash, &device->stats.tx_bytes, &device->stats.tx_packets,
                      &device->stats.tx_errors, &device->stats.tx_dropped, &trash,
                      &device->stats.collisions, &trash, &trash );
    if ( ret != 16 ) {
      error( "Failed to retrieve interface statistics ( ret = %d, device = %s ).", ret, device->name );
      break;
    }
    found = true;
  }

  fclose( fh );

  return found;
}


static void
enable_promiscuous( ether_device *device ) {
  int fd = socket( AF_INET, SOCK_DGRAM, 0 );
  if ( fd < 0 ) {
    char error_string[ ERROR_STRING_SIZE ];
    error( "Failed to open a socket ( ret = %d, errno = %s [%d] ).",
           fd, safe_strerror_r( errno, error_string, sizeof( error_string ) ), errno );
    return;
  }

  struct ifreq ifr;

  memset( &ifr, 0, sizeof( ifr ) );
  strncpy( ifr.ifr_name, device->name, IFNAMSIZ );
  ifr.ifr_name[ IFNAMSIZ - 1 ] = '\0';

  int ret = ioctl( fd, SIOCGIFFLAGS, &ifr );
  if ( ret == -1 ) {
    char error_string[ ERROR_STRING_SIZE ];
    error( "Failed to get interface flags ( device = %s, ret = %d, errno = %s [%d] ).",
           ifr.ifr_name, ret, safe_strerror_r( errno, error_string, sizeof( error_string ) ), errno );
    close( fd );
    return;
  }

  ifr.ifr_flags |= IFF_PROMISC;
  ret = ioctl( fd, SIOCSIFFLAGS, &ifr );
  if ( ret == -1 ) {
    char error_string[ ERROR_STRING_SIZE ];
    error( "Failed to set interface flags ( device = %s, flags = %#x, ret = %d, errno = %s [%d] ).",
           ifr.ifr_name, ifr.ifr_flags, ret, safe_strerror_r( errno, error_string, sizeof( error_string ) ), errno );
    close( fd );
    return;
  }

  close( fd );
}


static void
handle_received_frames( ether_device *device ) {
  assert( device != NULL );

  while ( get_packet_buffers_length( device->recv_queue ) > 0 ) {
    buffer *frame = dequeue_packet_buffer( device->recv_queue );
    assert( frame != NULL );
    if ( device->received_callback != NULL ) {
      device->received_callback( frame, device->received_user_data );
    }
    mark_packet_buffer_as_used( device->recv_queue, frame );
  }
}


static void
receive_frame( int fd, void *user_data ) {
  UNUSED( fd );

  ether_device *device = user_data;
  assert( device != NULL );

  if ( !device->status.up ) {
    return;
  }

  if ( get_max_packet_buffers_length( device->recv_queue ) <= get_packet_buffers_length( device->recv_queue ) ) {
    warn( "Receive queue is full ( device = %s, usage = %u/%u ).", device->name,
          get_packet_buffers_length( device->recv_queue ), get_max_packet_buffers_length( device->recv_queue ) );
    return;
  }

  unsigned int count = 0;
  const unsigned int max_queue_length = get_max_packet_buffers_length( device->recv_queue );
  const unsigned int max_loop_count = max_queue_length < 256 ? max_queue_length : 256;
  while ( count < max_loop_count ) {
    buffer *frame = get_buffer_from_free_buffers( device->recv_queue );
    if ( frame == NULL ) {
      warn( "Failed to retrieve a receive buffer ( device = %s, queue usage = %u/%u ).", device->name,
            get_packet_buffers_length( device->recv_queue ), max_queue_length );
      frame = device->recv_buffer; // Use recv_buffer as a trash.
    }
    reset_buffer( frame );
    append_back_buffer( frame, device->mtu );

#if WITH_PCAP
    size_t length = 0;
    struct pcap_pkthdr *header = NULL;
    const u_char *packet = NULL;
    int ret = pcap_next_ex( device->pcap, &header, &packet );
    if ( ret == 1 ) {
      length = header->caplen;
      if ( length > frame->length ) {
        append_back_buffer( frame, length - frame->length );
      }
      memcpy( frame->data, packet, length );
    }
    else {
      if ( frame != device->recv_buffer ) {
        mark_packet_buffer_as_used( device->recv_queue, frame );
      }
      if ( ret == -1 ) {
        error( "Receive error ( device = %s, pcap_err = %s ).",
               device->name, pcap_geterr( device->pcap ) );
      }
      break;
    }
#else // WITH_PCAP
    struct msghdr msg;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;

    struct iovec iovec;
    size_t headroom_length = sizeof( vlantag_header_t );
    char *head = ( char * ) frame->data + headroom_length;
    iovec.iov_base = head;
    iovec.iov_len = frame->length - headroom_length;
    msg.msg_iov = &iovec;
    msg.msg_iovlen = 1;

    char cmsg_buf[ CMSG_SPACE( sizeof( struct tpacket_auxdata ) ) ];
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof( cmsg_buf );
    msg.msg_flags = 0;

    ssize_t length = recvmsg( device->fd, &msg, MSG_DONTWAIT );
    assert( length != 0 );
    if ( length < 0 ) {
      if ( frame != device->recv_buffer ) {
        mark_packet_buffer_as_used( device->recv_queue, frame );
      }
      if ( ( errno == EINTR ) || ( errno == EAGAIN ) || ( errno == EWOULDBLOCK ) || ( errno == ENETDOWN ) ) {
        break;
      }
      char error_string[ ERROR_STRING_SIZE ];
      error( "Receive error ( device = %s, errno = %s [%d] ).",
             device->name, safe_strerror_r( errno, error_string, sizeof( error_string ) ), errno );
      break;
    }

    for ( struct cmsghdr *cmsg = CMSG_FIRSTHDR( &msg ); cmsg != NULL; cmsg = CMSG_NXTHDR( &msg, cmsg ) ) {
      if ( cmsg->cmsg_len < CMSG_LEN( sizeof( struct tpacket_auxdata ) ) ) {
        continue;
      }
      if ( cmsg->cmsg_level != SOL_PACKET || cmsg->cmsg_type != PACKET_AUXDATA ) {
        continue;
      }
      struct tpacket_auxdata *auxdata = ( struct tpacket_auxdata * ) CMSG_DATA( cmsg );
      if ( auxdata->tp_vlan_tci == 0 ) {
        continue;
      }
      head -= sizeof( vlantag_header_t );
      if ( ( void * ) head < frame->data ) {
        append_front_buffer( frame, sizeof( vlantag_header_t ) );
        head = frame->data;
      }
      length += ( ssize_t ) sizeof( vlantag_header_t );
      memmove( head, head + sizeof( vlantag_header_t ), ETH_ADDRLEN * 2 );
      uint16_t *eth_type = ( uint16_t * ) ( head + ETH_ADDRLEN * 2 );
      *eth_type = htons( ETH_P_8021Q );
#ifdef TP_STATUS_VLAN_TPID_VALID
      if ( ( auxdata->tp_vlan_tpid != 0 ) && ( auxdata->tp_status & TP_STATUS_VLAN_TPID_VALID ) ) {
        *eth_type = htons( auxdata->tp_vlan_tpid );
      }
#endif
      uint16_t *tci = ++eth_type;
      *tci = htons( auxdata->tp_vlan_tci );
    }
    frame->data = head;
#endif
    if ( frame != device->recv_buffer ) {
      frame->length = ( size_t ) length;
      enqueue_packet_buffer( device->recv_queue, frame );
    }
    count++;
  }

  handle_received_frames( device );
}


static void
flush_send_queue( int fd, void *user_data ) {
  UNUSED( fd );

  ether_device *device = user_data;
  assert( device != NULL );

  debug( "Flushing send queue ( device = %s, queue length = %u ).", device->name, get_packet_buffers_length( device->send_queue ) );

  set_writable_safe( device->fd, false );

  struct sockaddr_ll sll;
  memset( &sll, 0, sizeof( sll ) );
  sll.sll_ifindex = device->ifindex;

  int count = 0;
  buffer *buf = NULL;
  while ( ( buf = peek_packet_buffer( device->send_queue ) ) != NULL && count < 256 ) {
#if WITH_PCAP
    if( pcap_sendpacket( device->pcap, buf->data, ( int ) buf->length ) < 0 ){
      error( "Failed to send a message to ethernet device ( device = %s, pcap_err = %s ).",
             device->name, pcap_geterr( device->pcap ) );
    }
    size_t length = buf->length;
#else
    ssize_t length = sendto( device->fd, buf->data, buf->length, MSG_DONTWAIT, ( struct sockaddr * ) &sll, sizeof( sll ) );
    if ( length < 0 ) {
      if ( ( errno == EINTR ) || ( errno == EAGAIN ) || ( errno == EWOULDBLOCK ) ) {
        break;
      }
      char error_string[ ERROR_STRING_SIZE ];
      error( "Failed to send a message to ethernet device ( device = %s, errno = %s [%d] ).",
             device->name, safe_strerror_r( errno, error_string, sizeof( error_string ) ), errno );
      return;
    }
#endif

    if ( ( size_t ) length < buf->length ) {
      remove_front_buffer( buf, ( size_t ) length );
      break;
    }

    buf = dequeue_packet_buffer( device->send_queue );
    mark_packet_buffer_as_used( device->send_queue, buf );
    count++;
  }
  if ( get_packet_buffers_length( device->send_queue ) > 0 ) {
    set_writable_safe( device->fd, true );
  }
}


ether_device *
create_ether_device( const char *name, const size_t max_send_queue, const size_t max_recv_queue ) {
  assert( name != NULL );
  assert( strlen( name ) > 0 );
  assert( max_send_queue > 0 );
  assert( max_recv_queue > 0 );

  int nfd = socket( PF_INET, SOCK_DGRAM, 0 );
  if ( nfd < 0 ) {
    char error_string[ ERROR_STRING_SIZE ];
    error( "Failed to open a socket ( ret = %d, errno = %s [%d] ).",
           nfd, safe_strerror_r( errno, error_string, sizeof( error_string ) ), errno );
    return NULL;
  }

  struct ifreq ifr;
  memset( &ifr, 0, sizeof( ifr ) );
  strncpy( ifr.ifr_name, name, IFNAMSIZ );
  ifr.ifr_name[ IFNAMSIZ - 1 ] = '\0';
  int ret = ioctl( nfd, SIOCGIFINDEX, &ifr );
  if ( ret == -1 ) {
    char error_string[ ERROR_STRING_SIZE ];
    error( "Failed to retrieve an interface index of %s ( ret = %d, errno = %s [%d] ).",
           name, ret, safe_strerror_r( errno, error_string, sizeof( error_string ) ), errno );
    close( nfd );
    return NULL;
  }
  int ifindex = ifr.ifr_ifindex;

  ret = ioctl( nfd, SIOCGIFMTU, &ifr );
  if ( ret == -1 ) {
    char error_string[ ERROR_STRING_SIZE ];
    error( "Failed to retrieve MTU of %s ( ret = %d, errno = %s [%d] ).",
            name, ret, safe_strerror_r( errno, error_string, sizeof( error_string ) ), errno );
    close( nfd );
    return NULL;
  }
  int mtu = ifr.ifr_mtu;

  ret = ioctl( nfd, SIOCGIFHWADDR, &ifr );
  if ( ret == -1 ) {
    char error_string[ ERROR_STRING_SIZE ];
    error( "Failed to retrieve hardware address of %s ( ret = %d, error = %s [%d] ).",
           name, ret, safe_strerror_r( errno, error_string, sizeof( error_string ) ), errno );
    close( nfd );
    return NULL;
  }

  close( nfd );

  size_t device_mtu = ( size_t ) mtu + MAX_L2_HEADER_LENGTH;
#ifdef WITH_PCAP
  char errbuf[ PCAP_ERRBUF_SIZE ];
  pcap_t *handle = pcap_create( name, errbuf );
  if( handle == NULL ){
    error( "Failed to open %s ( %s ).", name, errbuf );
    return NULL;
  }
  if ( pcap_set_snaplen( handle, ( int ) device_mtu ) < 0 ) {
    warn( "Failed to set MTU for %s.", name );
  }
  if ( pcap_set_promisc( handle, 1 ) < 0 ) {
    warn( "Failed to set PROMISC for %s.", name );
  }
  if ( pcap_set_timeout( handle, 100 ) < 0 ) {
    warn( "Failed to set timeout for %s.", name );
  }
  #ifdef USE_PCAP_IMMEDIATE_MODE // TPACKET_V3 do buffers
  if ( pcap_set_immediate_mode( handle, 1 ) < 0 ) {
    warn( "Failed to set immediate mode for %s.", name );
  }
  #endif // USE_PCAP_IMMEDIATE_MODE
  if ( pcap_activate( handle ) < 0 ) {
    error( "Failed to activate %s.", name );
    pcap_close( handle );
    return NULL;
  }
  if ( pcap_setnonblock( handle, 1, errbuf ) == -1 ) {
    warn( "Failed to setnonblock %s ( %s ).", name, errbuf );
  }

  int fd = pcap_get_selectable_fd( handle );
#else // WITH_PCAP
  int fd = socket( PF_PACKET, SOCK_RAW, htons( ETH_P_ALL ) );
  if ( fd < 0 ) {
    char error_string[ ERROR_STRING_SIZE ];
    error( "Failed to open a socket ( ret = %d, errno = %s [%d] ).",
           fd, safe_strerror_r( errno, error_string, sizeof( error_string ) ), errno );
    return NULL;
  }

  struct sockaddr_ll sll;
  memset( &sll, 0, sizeof( sll ) );
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons( ETH_P_ALL );
  sll.sll_ifindex = ifindex;
  ret = bind( fd, ( struct sockaddr * ) &sll, sizeof( sll ) );
  if ( ret < 0 ) {
    char error_string[ ERROR_STRING_SIZE ];
    error( "Failed to bind ( fd = %d, ret = %d, errno = %s [%d] ).",
           fd, ret, safe_strerror_r( errno, error_string, sizeof( error_string ) ), errno );
    close( fd );
    return NULL;
  }

  int val = TPACKET_V2;
  ret = setsockopt( fd, SOL_PACKET, PACKET_VERSION, &val, sizeof( val ) );
  if ( ret < 0 ) {
    char error_string[ ERROR_STRING_SIZE ];
    error( "Failed to set PACKET_VERSION to %d ( fd = %d, ret = %d, errno = %s [%d] ).",
           val, fd, ret, safe_strerror_r( errno, error_string, sizeof( error_string ) ), errno );
    close( fd );
    return NULL;
  }

  val = 1;
  ret = setsockopt( fd, SOL_PACKET, PACKET_AUXDATA, &val, sizeof( val ) );
  if ( ret < 0 ) {
    char error_string[ ERROR_STRING_SIZE ];
    error( "Failed to set PACKET_AUXDATA to %d ( fd = %d, ret = %d, errno = %s [%d] ).",
           val, fd, ret, safe_strerror_r( errno, error_string, sizeof( error_string ) ), errno );
    close( fd );
    return NULL;
  }

  while ( 1 ) {
    char buf;
    ssize_t length = recv( fd, &buf, 1, MSG_DONTWAIT );
    if ( length <= 0 ) {
      break;
    }
  }
#endif // WITH_PCAP

  ether_device *device = xmalloc( sizeof( ether_device ) );
  memset( device, 0, sizeof( ether_device ) );
  strncpy( device->name, name, IFNAMSIZ );
  device->name[ IFNAMSIZ - 1 ] = '\0';
#if WITH_PCAP
  device->pcap = handle;
#endif
  device->fd = fd;
  device->ifindex = ifindex;
  memcpy( device->hw_addr, ifr.ifr_hwaddr.sa_data, ETH_ADDRLEN );
  device->status.can_retrieve_link_status = true;
  device->status.can_retrieve_pause = true;
  device->mtu = device_mtu;
  device->recv_buffer = alloc_buffer_with_length( device->mtu );
  device->send_queue = create_packet_buffers( ( unsigned int ) max_send_queue, device->mtu );
  device->recv_queue = create_packet_buffers( ( unsigned int ) max_recv_queue, device->mtu );

  short int flags = get_device_flags( device->name );
  device->original_flags = flags;

  set_fd_handler_safe( fd, receive_frame, device, flush_send_queue, device );
  set_readable_safe( fd, true );

  enable_promiscuous( device );
  up_ether_device( device );
  update_device_status( device );

  time_now( &device->created_at );

  return device;
}


void
delete_ether_device( ether_device *device ) {
  assert( device != NULL );

#if WITH_PCAP
  if ( device->pcap != NULL ) {
    pcap_close( device->pcap );
    device->pcap = NULL;
  }
#endif
  if ( device->fd >= 0 ) {
    set_readable_safe( device->fd, false );
    if ( get_packet_buffers_length( device->send_queue ) > 0 ) {
      set_writable_safe( device->fd, false );
    }
    delete_fd_handler_safe( device->fd );
    close( device->fd );
  }

  if ( device->recv_buffer != NULL ) {
    free_buffer( device->recv_buffer );
  }

  set_device_flags( device->name, device->original_flags );

  delete_packet_buffers( device->send_queue );
  delete_packet_buffers( device->recv_queue );

  xfree( device );
}


short int
get_device_flags( const char *name ) {
  assert( name != NULL );

  int fd = socket( AF_INET, SOCK_DGRAM, 0 );

  struct ifreq ifr;
  memset( &ifr, 0, sizeof( ifr ) );
  strncpy( ifr.ifr_name, name, IFNAMSIZ );
  ifr.ifr_name[ IFNAMSIZ - 1 ] = '\0';

  int ret = ioctl( fd, SIOCGIFFLAGS, &ifr );
  if ( ret == -1 ) {
    char error_string[ ERROR_STRING_SIZE ];
    error( "Failed to get interface flags ( device = %s, ret = %d, errno = %s [%d] ).",
           ifr.ifr_name, ret, safe_strerror_r( errno, error_string, sizeof( error_string ) ), errno );
  }

  close( fd );

  return ifr.ifr_flags;
}


bool
set_device_flags( const char *name, short int flags ) {
  assert( name != NULL );

  int fd = socket( AF_INET, SOCK_DGRAM, 0 );

  struct ifreq ifr;
  memset( &ifr, 0, sizeof( ifr ) );
  strncpy( ifr.ifr_name, name, IFNAMSIZ );
  ifr.ifr_name[ IFNAMSIZ - 1 ] = '\0';

  ifr.ifr_flags = flags;
  int ret = ioctl( fd, SIOCSIFFLAGS, &ifr );
  if ( ret == -1 ) {
    char error_string[ ERROR_STRING_SIZE ];
    error( "Failed to set interface flags ( device = %s, flags = %#x, ret = %d, errno = %s [%d] ).",
           ifr.ifr_name, ifr.ifr_flags, ret, safe_strerror_r( errno, error_string, sizeof( error_string ) ), errno );
    close( fd );
    return false;
  }

  close( fd );

  return true;
}


bool
up_ether_device( ether_device *device ) {
  assert( device != NULL );
  assert( device->name != NULL );

  short int flags = get_device_flags( device->name );
  if ( ( flags & IFF_UP ) == 0 ) {
    flags |= IFF_UP;
  }
  if ( ( flags & IFF_RUNNING ) == 0 ) {
    flags |= IFF_RUNNING;
  }

  return set_device_flags( device->name, flags );
}


bool
down_ether_device( ether_device *device ) {
  assert( device != NULL );

  assert( device != NULL );
  assert( device->name != NULL );

  short int flags = get_device_flags( device->name );
  if ( flags & IFF_UP ) {
    flags &= ~IFF_UP;
  }
  if ( flags & IFF_RUNNING ) {
    flags &= ~IFF_RUNNING;
  }

  return set_device_flags( device->name, flags );
}


bool
send_frame( ether_device *device, buffer *frame ) {
  assert( device != NULL );
  assert( device->send_queue != NULL );
  assert( frame != NULL );
  assert( frame->length > 0 );

  if ( get_max_packet_buffers_length( device->send_queue ) <= get_packet_buffers_length( device->send_queue ) ) {
    warn( "Send queue is full ( device = %s, usage = %u/%u ).",
          device->name, get_packet_buffers_length( device->send_queue ), get_max_packet_buffers_length( device->send_queue ) );
    return false;
  }

  debug( "Enqueueing a frame to send queue ( frame = %p, device = %s, queue length = %d, fd = %d ).",
         frame, device->name, get_packet_buffers_length( device->send_queue ), device->fd );

  buffer *copy = get_free_packet_buffer( device->send_queue );
  assert( copy != NULL );
  copy_buffer( copy, frame );

  enqueue_packet_buffer( device->send_queue, copy );

  if ( ( get_packet_buffers_length( device->send_queue ) > 0 ) && ( device->fd >= 0 ) ) {
    set_writable_safe( device->fd, true );
  }

  return true;
}


bool
set_frame_received_handler( ether_device *device, frame_received_handler callback, void *user_data ) {
  assert( device != NULL );
  assert( callback != NULL );

  device->received_callback = callback;
  device->received_user_data = user_data;

  return true;
}


struct timespec
get_device_uptime( ether_device *device ) {
  assert( device != NULL );

  struct timespec now = { 0, 0 };
  time_now( &now );
  struct timespec diff = { 0, 0 };
  timespec_diff( device->created_at, now, &diff );

  return diff;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
