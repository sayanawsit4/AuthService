package com.lnl.repository;

import com.lnl.domain.AccessAudit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.UUID;

public interface AuditRepository extends JpaRepository<AccessAudit, UUID> {

    @Query("select count(*) from AccessAudit t where t.userId = ?1")
    Integer countByemail(UUID userId);

}
