package com.example.auditapi.Service;

import com.example.auditapi.Model.AuditEvent;
import com.example.auditapi.Repository.AuditEventRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class AuditEventService {

    @Autowired
    private AuditEventRepository repository;

    // Get all events
    public List<AuditEvent> getAllEvents() {
        return repository.findAll();
    }

    // Get event by ID
    public Optional<AuditEvent> getEventById(Long id) {
        return repository.findById(id);
    }

    // Create event
    public AuditEvent createEvent(AuditEvent event) {
        return repository.save(event);
    }

    // Search by event type
    public List<AuditEvent> getEventsByType(String eventType) {
        return repository.findByEventType(eventType);
    }

    // Search by user
    public List<AuditEvent> getEventsByUser(String userId) {
        return repository.findByUserId(userId);
    }

    // Search by status
    public List<AuditEvent> getEventsByStatus(String status) {
        return repository.findByStatus(status);
    }

    // Search by severity
    public List<AuditEvent> getEventsBySeverity(String severity) {
        return repository.findBySeverity(severity);
    }

    // Search by date range
    public List<AuditEvent> getEventsByDateRange(LocalDateTime start, LocalDateTime end) {
        return repository.findByTimestampBetween(start, end);
    }

    // Get statistics
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();

        // Total events
        stats.put("totalEvents", repository.count());

        // By event type
        stats.put("loginEvents", repository.countByEventType("LOGIN"));
        stats.put("logoutEvents", repository.countByEventType("LOGOUT"));
        stats.put("dataAccessEvents", repository.countByEventType("DATA_ACCESS"));
        stats.put("transferEvents", repository.countByEventType("TRANSFER"));
        stats.put("errorEvents", repository.countByEventType("ERROR"));

        // By status
        stats.put("successEvents", repository.countByStatus("SUCCESS"));
        stats.put("failureEvents", repository.countByStatus("FAILURE"));
        stats.put("pendingEvents", repository.countByStatus("PENDING"));

        // By severity
        stats.put("infoEvents", repository.countBySeverity("INFO"));
        stats.put("warningEvents", repository.countBySeverity("WARNING"));
        stats.put("errorSeverityEvents", repository.countBySeverity("ERROR"));
        stats.put("criticalEvents", repository.countBySeverity("CRITICAL"));

        return stats;
    }
}