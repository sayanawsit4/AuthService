package com.lnl.repository;

import com.lnl.domain.AttemptCounter;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

public interface AttemptCounterRepository extends JpaRepository<AttemptCounter, UUID> {

    @Query("select counter from AttemptCounter t where t.userId = ?1")
    Integer countByUserId(UUID userId);
}
