// Copyright 2003-2005 Arthur van Hoff, Rick Blair
// Licensed under Apache License version 2.0
// Original license LGPL

package javax.jmdns.impl.tasks;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jmdns.ServiceInfo;
import javax.jmdns.impl.*;
import javax.jmdns.impl.constants.DNSConstants;
import javax.jmdns.impl.constants.DNSRecordType;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.*;

/**
 * The Responder sends a single answer for the specified service infos and for the host name.
 */
public class Responder extends DNSTask {
    static Logger             logger = LoggerFactory.getLogger(Responder.class.getName());

    /**
     *
     */
    private final DNSIncoming _in;

    /**
     * The incoming address and port.
     */
    private final InetAddress _addr;
    private final int         _port;

    /**
     *
     */
    private final boolean     _unicast;

    public Responder(JmDNSImpl jmDNSImpl, DNSIncoming in, InetAddress addr, int port) {
        super(jmDNSImpl);
        this._in = in;
        this._addr = addr;
        this._port = port;
        this._unicast = (port != DNSConstants.MDNS_PORT);
    }

    /*
     * (non-Javadoc)
     * @see javax.jmdns.impl.tasks.DNSTask#getName()
     */
    @Override
    public String getName() {
        return "Responder(" + (this.getDns() != null ? this.getDns().getName() : "") + ")";
    }

    /*
     * (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return super.toString() + " incomming: " + _in;
    }

    /*
     * (non-Javadoc)
     * @see javax.jmdns.impl.tasks.DNSTask#start(java.util.Timer)
     */
    @Override
    public void start(Timer timer) {
        // According to draft-cheshire-dnsext-multicastdns.txt chapter "7 Responding":
        // We respond immediately if we know for sure, that we are the only one who can respond to the query.
        // In all other cases, we respond within 20-120 ms.
        //
        // According to draft-cheshire-dnsext-multicastdns.txt chapter "6.2 Multi-Packet Known Answer Suppression":
        // We respond after 20-120 ms if the query is truncated.

        boolean iAmTheOnlyOne = true;
        for (DNSQuestion question : _in.getQuestions()) {
            logger.trace("{}.start() question={}", this.getName(), question);
            iAmTheOnlyOne = question.iAmTheOnlyOne(this.getDns());
            if (!iAmTheOnlyOne) {
                break;
            }
        }
        int delay = (iAmTheOnlyOne && !_in.isTruncated()) ? 0 : DNSConstants.RESPONSE_MIN_WAIT_INTERVAL + JmDNSImpl.getRandom().nextInt(DNSConstants.RESPONSE_MAX_WAIT_INTERVAL - DNSConstants.RESPONSE_MIN_WAIT_INTERVAL + 1) - _in.elapseSinceArrival();
        if (delay < 0) {
            delay = 0;
        }
        logger.trace("{}.start() Responder chosen delay={}", this.getName(), delay);

        if (!this.getDns().isCanceling() && !this.getDns().isCanceled()) {
            timer.schedule(this, delay);
        }
    }

    @Override
    public void run() {
        this.getDns().respondToQuery(_in);
        // Store source information because it might change later
        String srcAddress = _in.getSrcAddress();
        int srcPort = _in.getSrcPort();

        // We use these sets to prevent duplicate records
        Set<DNSQuestion> questions = new HashSet<DNSQuestion>();
        Set<DNSRecord> answers = new HashSet<DNSRecord>();
        Collection<? extends DNSQuestion> inQuestions = _in.getQuestions();

        if (this.getDns().isAnnounced()) {
            try {
                // Answer questions
                for (DNSQuestion question : inQuestions) {
                    logger.debug("{}.run() JmDNS responding to: {}", this.getName(), question);

                    // for unicast responses the question must be included
                    if (_unicast) {
                        // out.addQuestion(q);
                        questions.add(question);
                    }

                    question.addAnswers(this.getDns(), answers);
                }

                if (this.getDns().isUnicast()) logger.debug("Found " + answers.size() + " answers for IP " + srcAddress);

                // remove known answers, if the TTL is at least half of the correct value. (See Draft Cheshire chapter 7.1.).
                long now = System.currentTimeMillis();
                for (DNSRecord knownAnswer : _in.getAnswers()) {
                    if (knownAnswer.isStale(now)) {
                        answers.remove(knownAnswer);
                        logger.debug("{} - JmDNS Responder Known Answer Removed", this.getName());
                    }
                }

                // Remove answers from services that are not paired to that IP (could be better to just not add them at all)
                List<String> serviceKeysMatchingSrcIp = this.getDns().serviceInfosBySrcIpAddress.get((Inet4Address) Inet4Address.getByName(srcAddress));
                if (this.getDns().isUnicast()) {
                    List<DNSRecord> toRemove = new ArrayList<DNSRecord>();
                    List<String> serviceServersMatchingSrcIp = new ArrayList<String>(); // with dashes
                    if (serviceKeysMatchingSrcIp != null) {
                        for (String serviceKeyMatchingSrcIp: serviceKeysMatchingSrcIp) {
                            ServiceInfo s = this.getDns().getServices().get(serviceKeyMatchingSrcIp);
                            if (s != null && s.getServer() != null) serviceServersMatchingSrcIp.add(s.getServer());
                        }
                    }
                    for (DNSRecord answer : answers) {
                        boolean match = false;
                        for (String server: serviceServersMatchingSrcIp) {
                            if (answer instanceof DNSRecord.IPv4Address && answer.getKey().contains(server)) {
                                match = true;
                            }
                        }
                        if (serviceKeysMatchingSrcIp != null) {
                            for (String serviceKey : serviceKeysMatchingSrcIp) {
                                if (answer.getServiceInfo().getKey().contains(serviceKey)) {
                                    match = true;
                                }
                            }
                        }
                        if (!match) toRemove.add(answer);
                    }
                    if (!answers.isEmpty()) logger.info("Pruning " + toRemove.size() + "/" + answers.size() + " answers for IP " + srcAddress + " (matching services = " + serviceKeysMatchingSrcIp + ")");
                    answers.removeAll(toRemove);
                }

                // respond if we have answers
                if (!answers.isEmpty()) {
                    logger.debug("{}.run() JmDNS responding", this.getName());

                    DNSOutgoing out = new DNSOutgoing(DNSConstants.FLAGS_QR_RESPONSE | DNSConstants.FLAGS_AA, !_unicast, _in.getSenderUDPPayload());
                    if (this.getDns().isUnicast()) {
                        out.setDestination(new InetSocketAddress(srcAddress, srcPort));
                    } else if (_unicast) {
                        out.setDestination(new InetSocketAddress(_addr, _port)); // this does not seem to work, _addr and _port are supposed to be the source but seem to be the multicast destination
                    }
                    out.setId(_in.getId());
                    for (DNSQuestion question : questions) {
                        if (question != null) {
                            out = this.addQuestion(out, question);
                        }
                    }
                    for (DNSRecord answer : answers) {
                        if (answer != null) {
                            if (answer.getRecordType().equals(DNSRecordType.TYPE_PTR)) out = this.addAnswer(out, _in, answer);
                            else out = this.addAdditionalAnswer(out, _in, answer);
                        }
                    }
                    if (!out.isEmpty()) {
                        this.getDns().send(out);

                        if (this.getDns().isUnicast()) {
                            // Add other answers for e.g. _233637DE._sub._googlecast._tcp.local
                            if (out.getAnswers().iterator().hasNext()) {
                                DNSRecord baseAnswer = out.getAnswers().iterator().next();
                                for (DNSQuestion question : inQuestions) {
                                    if (question.getName().contains("._sub._googlecast._tcp") && !question.getName().startsWith("_%")) {
                                        out.getAnswers().clear();
                                        baseAnswer.setName(question.getName());
                                        out.addAnswer(_in, baseAnswer);
                                        this.getDns().send(out);
                                    }
                                }
                            } else {
                                logger.warn("No subAnswer found");
                            }
                        }
                    }
                }
                // this.cancel();
            } catch (Throwable e) {
                logger.warn(this.getName() + "run() exception ", e);
                this.getDns().close();
            }
        }
    }
}
