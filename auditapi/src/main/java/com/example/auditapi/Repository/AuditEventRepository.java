package com.example.auditapi.Repository;

import com.example.auditapi.Model.AuditEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AuditEventRepository extends JpaRepository<AuditEvent, Long> {

    // Find by event type
    List<AuditEvent> findByEventType(String eventType);

    // Find by user
    List<AuditEvent> findByUserId(String userId);

    // Find by status
    List<AuditEvent> findByStatus(String status);

    // Find by severity
    List<AuditEvent> findBySeverity(String severity);

    // Find by date range
    List<AuditEvent> findByTimestampBetween(LocalDateTime start, LocalDateTime end);

    // Count by event type
    @Query("SELECT COUNT(e) FROM AuditEvent e WHERE e.eventType = ?1")
    long countByEventType(String eventType);

    // Count by status
    @Query("SELECT COUNT(e) FROM AuditEvent e WHERE e.status = ?1")
    long countByStatus(String status);

    // Count by severity
    @Query("SELECT COUNT(e) FROM AuditEvent e WHERE e.severity = ?1")
    long countBySeverity(String severity);
}