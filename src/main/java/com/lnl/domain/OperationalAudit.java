package com.lnl.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.Date;
import java.util.UUID;

@Data
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "operational_audit", schema = "lnlauth2")
public class OperationalAudit {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "ops_audit_rec_no")
    private UUID opsAuditNo;

    @Column(name = "target_user")
    private String user;

    @Column(name = "token_id")
    private String tokenId;

    @Column(name = "ops_performed_by")
    private String opsPerformedBy;

    @Column(name = "client_id")
    private String clientId;

    @Column(name = "created_time")
    @Temporal(TemporalType.TIMESTAMP)
    private Date createdTime;

    @Column(name = "remote_ip")
    private String remoteIP;

    @Column(name = "user_agent")
    private String userAgent;

    @Column(name = "url")
    private String url;

    @Column(name = "status")
    private String status;

    @Column(name = "scope")
    private String scope;

    @Column(name = "response")
    private String response;
}