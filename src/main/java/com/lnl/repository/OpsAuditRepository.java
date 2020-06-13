package com.lnl.repository;

import com.lnl.domain.OperationalAudit;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface OpsAuditRepository extends JpaRepository<OperationalAudit, UUID> {

}
