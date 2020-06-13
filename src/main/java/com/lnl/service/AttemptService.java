package com.lnl.service;

import com.lnl.repository.AttemptCounterRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;


@Slf4j
@Service
public class AttemptService {
    @Autowired
    private AttemptCounterRepository attemptCounterRepository;

    @Value("${audit.maxLockdownPeriod}")
    private Double maxLockDownPeriod;

    @Value("${audit.maxVaiableAttempt}")
    private Double maxViableAttempt;

    public double calculateLockDown(UUID userId) {
        Optional<Integer> count = Optional.ofNullable(attemptCounterRepository.countByUserId(userId));
        double finalCal = 0;
        if (count.isPresent()) {
            log.info("attemptCounterRepository----------------is"+attemptCounterRepository.countByUserId(userId));
            finalCal = Math.pow(2, (attemptCounterRepository.countByUserId(userId) - 2));
            if (finalCal > maxLockDownPeriod)
                finalCal = maxLockDownPeriod;
        }
        return finalCal;
    }

    public Boolean isMaxAttemptReached(UUID userId) {
        return attemptCounterRepository.countByUserId(userId) > maxViableAttempt;
    }

    public boolean isBlocked(UUID userId, Optional<Timestamp> lastAttemptTime) {
        Date date = new Date();
        if (lastAttemptTime.isPresent() && isMaxAttemptReached(userId)) {
            long milliseconds = new Timestamp(date.getTime()).getTime() - lastAttemptTime.get().getTime();
            log.info("now-------->" + date.getTime());
            log.info("lastAttemptTime-------->" + lastAttemptTime.get().getTime());
            int seconds = (int) milliseconds / 1000;
            double minutes = (seconds % 3600d) / 60;
            log.info("minutes-------->" + minutes);
            log.info("calculateLockDown-------->" + calculateLockDown(userId));
            return minutes < calculateLockDown(userId);
        } else {
            return false;
        }
    }
}
