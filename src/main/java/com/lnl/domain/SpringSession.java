package com.lnl.domain;

import lombok.AllArgsConstructor;
import lombok.Data;

import javax.persistence.*;
import java.io.Serializable;

@Entity
@AllArgsConstructor
@Data
@Table(name = "spring_session", schema = "lnlauth2")
public class SpringSession implements Serializable {

    @Id
    private String sessionId;

    @Column(name = "principal_name")
    private String principalName;

    @Column(name = "max_inactive_interval")
    private Long maxInactiveInterval;

    @Column(name = "last_access_time")
    private Long lastAccessTime;

    @Column(name = "expiry_time")
    private Long expiryTime;

    @Column(name = "creation_time")
    private Long creationTime;

}