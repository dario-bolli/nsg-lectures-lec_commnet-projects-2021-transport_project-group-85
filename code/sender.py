"""A Sender for the GBN protocol."""

# Disable pylint rules which are incompatible with our naming conventions
# pylint: disable=C0103,W0221,W0201,R0902,R0913,R0201

import argparse
import queue as que
import logging
import time
from scapy.sendrecv import send
from scapy.config import conf
from scapy.layers.inet import IP, ICMP
from scapy.packet import Packet, bind_layers
from scapy.fields import (BitEnumField, BitField, ShortField, ByteField,
                          ConditionalField)
from scapy.automaton import Automaton, ATMT

FORMAT = "[SENDER:%(lineno)3s - %(funcName)10s()] %(message)s"
logging.basicConfig(format=FORMAT)
log = logging.getLogger('sender')
log.setLevel(logging.DEBUG)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

TIMEOUT = 1  # number of seconds before packets are retransmitted


# Function that is called in the GBNSender's state machine's SEND state.
def on_send(sender, payload):
    sequence_number = sender.current
    send_gbn(sender, payload, sequence_number)


# Function that is called in the GBNSender's state machine's ACK_IN state.
def on_ack_in(sender, ack, does_receiver_use_sack=0, ack_blocks=[]):
    # If we receive an ack for a message in the send buffer, we update the unack variable and
    # remove all the cumulative acknowledged messages. Also, we reset the ACK counter.
    if previous_sequence_number(ack, sender) in sender.buffer:
        sender.unack = ack
        sender.ack_count = 1
        remove_all_acknowledged_messages_from_buffer(sender)
    elif ack == sender.unack:
        # Increment the ACK counter for duplicated ACKs.
        sender.ack_count = sender.ack_count + 1
    # else: for unexpected ACKs (ACKs for which no data segment was sent), we do not modify the
    # unack variable nor do we reset the ACK counter.

    # If applicable, resend missing data segments based on the selective acknowledgement.
    if sender.SACK:
        if does_receiver_use_sack:
            for key, payload in unacknowledged_messages(sender, ack_blocks).items():
                send_gbn(sender, payload,  key)

    # If applicable, resend data segments based on the selective repeat method.
    elif should_selective_repeat(sender):
        if sender.unack in sender.buffer:
            send_gbn(sender, sender.buffer[sender.unack], sender.unack)
        else:
            log.error(f"Sequence number {sender.unack} not found in send buffer "
                      f"{sender.buffer.keys()} for selective repeat.")

    if sender.Q_4_4:
        update_congestion_window_on_duplicated_ack(sender)


# Function that is called in the GBNSender's state machine's RETRANSMIT state.
def on_retransmit(sender):
    if sender.Q_4_4:
        # The sender's congestion window has size one. Therefore we only resend one segment.
        assert sender.unack in sender.buffer, f"Segment {sender.unack} not in buffer {sender.buffer}."
        send_gbn(sender, sender.buffer[sender.unack], sender.unack)
        log.debug(f"Resending {sender.unack}")

    else:
        for seq, payload in sender.buffer.items():
            send_gbn(sender, payload, seq)


def on_timeout(sender):
    if sender.Q_4_4:
        update_congestion_window_on_timeout(sender)


def send_gbn(sender, payload, sequence_number):
    # Only send if the sender is the real sender. For a mock sender in the
    # unit tests, just do nothing.
    if isinstance(sender, GBNSender):
        header = create_gbn_data_header(sender, payload, sequence_number)
        send(IP(src=sender.sender, dst=sender.receiver) / header / payload)


def create_gbn_data_header(sender, payload, sequence_number):
    segment_type = "data"
    options = sender.SACK
    length = len(payload)
    assert 0 < length <= 64     # Segments are 64 bytes execpt for the last one.
    hlen = 6                    # Header length without optional header
    num = sequence_number
    win = sender.win
    return GBN(type=segment_type, options=options, len=length,
               hlen=hlen, num=num, win=win)


# Removes all cumulative acknowledged messages from the sender's buffer based on the sender's
# unack value.
def remove_all_acknowledged_messages_from_buffer(sender):
    prev = previous_sequence_number(sender.unack, sender)
    while prev in sender.buffer:
        del sender.buffer[prev]
        prev = previous_sequence_number(prev, sender)

        if sender.Q_4_4:
            # Increase the congestion window for each successfully acknowleged data segment.
            increase_congestion_window(sender)


def should_selective_repeat(sender):
    return sender.Q_4_2 and sender.ack_count > 0 and sender.ack_count % 3 == 0


# Returns a list of SACK blocks
def extract_selective_acknowledgment_blocks(pkt):
    # The receiver communicates that it does not use SACK. Then we don't use SACK even if
    # the SACK blocks are present because it is more robust to not use SACK in presence of
    # a whacky receiver.
    if pkt.getlayer(GBN).options == 0:
        return []

    # If the receiver communicates to use SACK but no SACK block fits into the header, return
    # no SACK blocks.
    hlen = pkt.getlayer(GBN).hlen
    if hlen < 9:
        return []

    class SackBlock:
        def __init__(self, start, size):
            self.start = start
            self.size = size

    # In case of conflicting hlen and block_length variables, be conservative and choose
    # the lower number of blocks.
    block_length = min(pkt.getlayer(GBN).block_length, int((hlen - 6) / 3))

    ack_blocks = []
    if block_length >= 1:
        ack_blocks.append(SackBlock(pkt.getlayer(GBN).block_1_start,
                                    pkt.getlayer(GBN).block_1_size))
    if block_length >= 2:
        ack_blocks.append(SackBlock(pkt.getlayer(GBN).block_2_start,
                                    pkt.getlayer(GBN).block_2_size))
    if block_length == 3:
        ack_blocks.append(SackBlock(pkt.getlayer(GBN).block_3_start,
                                    pkt.getlayer(GBN).block_3_size))
    return ack_blocks


# Compute unacknowledged messages from selective acknowledgements blocks.
def unacknowledged_messages(sender, ack_blocks):
    if len(ack_blocks) == 0:
        return {}

    # Copy all possible segements for resending into the output variable. Afterwards, remove
    # what is already known to be acknowledged by the SACK blocks.
    output = sender.buffer.copy()

    # Do not retransmit messages inside the ack blocks.
    for block in ack_blocks:
        seq = block.start
        for i in range(0, block.size):
            if seq in output:
                del output[seq]
            else:
                log.error(f"Could not find {seq} in send buffer {sender.buffer.keys()} "
                          f"when handling the acknowledgement blocks {ack_blocks}.")
            seq = next_sequence_number(seq, sender)

    # Do not retransmit messages after the last ack block.
    seq = next_sequence_number(ack_blocks[-1].start, sender, steps=ack_blocks[-1].size)
    while seq in output:
        del output[seq]
        seq = next_sequence_number(seq, sender)

    return output


def next_sequence_number(seq, sender, steps=1):
    return int((seq + steps) % (2**sender.n_bits))


def previous_sequence_number(seq, sender):
    max_sequence_number = 2**sender.n_bits - 1
    return max_sequence_number if seq == 0 else seq - 1


def compute_window(sender):
    if sender.Q_4_4:
        return min(sender.win, sender.receiver_win, int(sender.cwnd))
    else:
        return min(sender.win, sender.receiver_win)


def increase_congestion_window(sender):
    log_cwnd(sender)        # Log cwnd value before increasing it.
    max_cwnd = sender.win
    if sender.cwnd < sender.ssthresh:
        # Multiplicative increase (slow start).
        sender.cwnd = min(sender.cwnd + 1.0, max_cwnd)
    else:
        # Additive increase.
        sender.cwnd = min(sender.cwnd + 1.0/sender.cwnd, max_cwnd)
    log_cwnd(sender)        # Log cwnd value after increasing it.


def update_congestion_window_on_duplicated_ack(sender):
    if sender.ack_count == 3:
        log_cwnd(sender)
        sender.cwnd = sender.cwnd / 2
        log_cwnd(sender)


def update_congestion_window_on_timeout(sender):
    log_cwnd(sender)
    sender.ssthresh = sender.cwnd / 2.0
    sender.cwnd = 1.0
    log_cwnd(sender)


def log_cwnd(sender):
    log.info(f"cwnd = {float(sender.cwnd)}, "
             f"time = {time.time()}, "
             f"ssthresh = {float(sender.ssthresh)}")


class GBN(Packet):
    """The GBN Header.

    It includes the following fields:
        type: DATA or ACK
        options: sack support
        len: payload length
        hlen: header length
        num: sequence/ACK number
        win: sender/receiver window size
    """
    name = 'GBN'
    fields_desc = [BitEnumField("type", 0, 1, {0: "data", 1: "ack"}),
                   BitField("options", 0, 7),
                   ShortField("len", None),
                   ByteField("hlen", 0),
                   ByteField("num", 0),
                   ByteField("win", 0),
                   ConditionalField(ByteField("block_length", 0), lambda pkt: pkt.hlen >= 7),
                   ConditionalField(ByteField("block_1_start", 0), lambda pkt: pkt.hlen >= 9),
                   ConditionalField(ByteField("block_1_size", 0), lambda pkt: pkt.hlen >= 9),
                   ConditionalField(ByteField("block_2_padding", 0), lambda pkt: pkt.hlen >= 12),
                   ConditionalField(ByteField("block_2_start", 0), lambda pkt: pkt.hlen >= 12),
                   ConditionalField(ByteField("block_2_size", 0), lambda pkt: pkt.hlen >= 12),
                   ConditionalField(ByteField("block_3_padding", 0), lambda pkt: pkt.hlen == 15),
                   ConditionalField(ByteField("block_3_start", 0), lambda pkt: pkt.hlen == 15),
                   ConditionalField(ByteField("block_3_size", 0), lambda pkt: pkt.hlen == 15)]



# GBN header is coming after the IP header
bind_layers(IP, GBN, frag=0, proto=222)


class GBNSender(Automaton):
    """Sender implementation for the GBN protocol using a Scapy automaton.

    Attributes:
        win: Maximum window size of the sender
        n_bits: number of bits used to encode sequence number
        receiver: IP address of the receiver
        sender: IP address of the sender
        q: Queue for all payload messages
        buffer: buffer to save sent but not acknowledged segments
        current: Sequence number of next data packet to send
        unack: First unacked segment
        receiver_win: Current window advertised by receiver, initialized with
                      sender window size
        Q_4_2: Is Selective Repeat used?
        SACK: Is SACK used?
        Q_4_4: Is Congestion Control used?
    """

    def parse_args(self, sender, receiver, n_bits, payloads, win,
                   Q_4_2, Q_4_3, Q_4_4, **kwargs):
        """Initialize Automaton."""
        Automaton.parse_args(self, **kwargs)
        self.win = win
        self.n_bits = n_bits
        assert self.win < 2**self.n_bits
        self.receiver = receiver
        self.sender = sender
        self.q = que.Queue()
        for item in payloads:
            self.q.put(item)

        self.buffer = {}
        self.current = 0
        self.unack = 0
        self.ack_count = 0
        self.cwnd = 1.0
        self.ssthresh = 2**n_bits  # Choose high intial value (infinite in theory).
        self.receiver_win = win
        self.Q_4_2 = Q_4_2
        self.SACK = Q_4_3
        self.Q_4_4 = Q_4_4

    def master_filter(self, pkt):
        """Filter packets of interest.

        Source has be the receiver and both IP and GBN headers are required.
        No ICMP packets.
        """
        return (IP in pkt and pkt[IP].src == self.receiver and GBN in pkt
                and ICMP not in pkt)

    @ATMT.state(initial=1)
    def BEGIN(self):
        """Start state of the automaton."""
        raise self.SEND()

    @ATMT.state(final=1)
    def END(self):
        """End state of the automaton."""
        log.debug("All packets successfully transmitted!")

    @ATMT.state()
    def SEND(self):
        """Main state of sender.

        New packets are transmitted to the receiver as long as there is space
        in the window.
        """
        # check if you still can send new packets to the receiver
        if len(self.buffer) < compute_window(self):
            try:
                # get next payload (automatically removes it from queue)
                payload = self.q.get(block=False)
                log.debug("Sending packet num: %s", self.current)

                # add the current segment to the buffer
                self.buffer[self.current] = payload
                log.debug("Current buffer size: %s", len(self.buffer))

                ###############################################################
                # TODO:                                                       #
                # create a GBN header with the correct header field values    #
                # send a packet to the receiver containing the created header #
                # and the corresponding payload                               #
                ###############################################################
                on_send(self, payload)

                # sequence number of next packet
                self.current = int((self.current + 1) % 2**self.n_bits)

                # back to the beginning of the state
                # (send next packet if possible)
                raise self.SEND()

            # no more payload pieces in the queue --> if all are acknowledged,
            # we can end the sender
            except que.Empty:
                if self.unack == self.current:
                    raise self.END()

    @ATMT.receive_condition(SEND)
    def packet_in(self, pkt):
        """Transition: Packet coming in from the receiver"""
        log.debug("Received packet: %s", pkt.getlayer(GBN).num)
        raise self.ACK_IN(pkt)

    @ATMT.state()
    def ACK_IN(self, pkt):
        """State for received ACK."""
        # check if type is ACK
        if pkt.getlayer(GBN).type == 0:
            log.error("Error: data type received instead of ACK %s", pkt)
            raise self.SEND()
        else:
            log.debug("Received ACK %s", pkt.getlayer(GBN).num)

            # set the receiver window size to the received value
            self.receiver_win = pkt.getlayer(GBN).win

            ack = pkt.getlayer(GBN).num

            ################################################################
            # TODO:                                                        #
            # remove all the acknowledged sequence numbers from the buffer #
            # make sure that you can handle a sequence number overflow     #
            ################################################################
            on_ack_in(sender=self, ack=ack, does_receiver_use_sack=pkt.getlayer(GBN).options,
                      ack_blocks=extract_selective_acknowledgment_blocks(pkt))

        # back to SEND state
        raise self.SEND()

    @ATMT.timeout(SEND, TIMEOUT)
    def timeout_reached(self):
        """Transition: Timeout is reached for first unacknowledged packet."""
        log.debug("Timeout for sequence number %s", self.unack)
        on_timeout(self)
        raise self.RETRANSMIT()

    @ATMT.state()
    def RETRANSMIT(self):
        """State for retransmitting packets."""

        ##############################################
        # TODO:                                      #
        # retransmit all the unacknowledged packets  #
        # (all the packets currently in self.buffer) #
        ##############################################
        on_retransmit(self)

        # back to SEND state
        raise self.SEND()


if __name__ == "__main__":
    # get input arguments
    parser = argparse.ArgumentParser('GBN sender')
    parser.add_argument('sender_IP', type=str,
                        help='The IP address of the sender')
    parser.add_argument('receiver_IP', type=str,
                        help='The IP address of the receiver')
    parser.add_argument('n_bits', type=int,
                        help='The number of bits used to encode the sequence '
                             'number field')
    parser.add_argument('input_file', type=str,
                        help='Path to the input file')
    parser.add_argument('window_size', type=int,
                        help='The window size of the sender')
    parser.add_argument('Q_4_2', type=int,
                        help='Use Selective Repeat (question 4.2)')
    parser.add_argument('Q_4_3', type=int,
                        help='Use Selective Acknowledgments (question 4.3)')
    parser.add_argument('Q_4_4', type=int,
                        help='Use Congestion Control (question 4.4/Bonus)')
    parser.add_argument('--interface', type=str, help='(optional) '
                        'interface to listen on')

    args = parser.parse_args()

    if args.interface:
        conf.iface = args.interface

    bits = args.n_bits
    assert bits <= 8

    in_file = args.input_file
    # list for binary payload
    payload_to_send_bin = list()
    # chunk size of payload
    chunk_size = 2**6

    # fill payload list
    with open(in_file, "rb") as file_in:
        while True:
            chunk = file_in.read(chunk_size)
            if not chunk:
                break
            payload_to_send_bin.append(chunk)

    # initial setup of automaton
    GBN_sender = GBNSender(args.sender_IP, args.receiver_IP, bits,
                           payload_to_send_bin, args.window_size, args.Q_4_2,
                           args.Q_4_3, args.Q_4_4)

    # start automaton
    GBN_sender.run()
