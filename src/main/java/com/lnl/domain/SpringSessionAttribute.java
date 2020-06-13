package com.lnl.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.hibernate.annotations.Type;

import javax.persistence.*;
import java.io.Serializable;

@Entity
@AllArgsConstructor
@Data
@Table(name = "spring_session_attributes", schema = "lnlauth2")
public class SpringSessionAttribute implements Serializable {

    @Id
    private String sessionId;

    @Id
    @Column(name = "attribute_name")
    private String attributeName;

    @Lob
    @Column(name = "attribute_bytes")
    @Type(type = "org.hibernate.type.BinaryType")
    private byte[] attributeBytes;

}