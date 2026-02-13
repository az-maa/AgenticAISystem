package com.example.auditapi.Controller;
import com.example.auditapi.Model.AuditEvent;
import com.example.auditapi.Service.AuditEventService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/audit")
@CrossOrigin(origins = "*")
public class AuditEventController {

    @Autowired
    private AuditEventService service;

    // Get all events
    @GetMapping("/events")
    public ResponseEntity<List<AuditEvent>> getAllEvents() {
        return ResponseEntity.ok(service.getAllEvents());
    }

    // Get event by ID
    @GetMapping("/events/{id}")
    public ResponseEntity<AuditEvent> getEventById(@PathVariable Long id) {
        return service.getEventById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // Create new event
    @PostMapping("/events")
    public ResponseEntity<AuditEvent> createEvent(@RequestBody AuditEvent event) {
        AuditEvent created = service.createEvent(event);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    // Search by event type
    @GetMapping("/events/type/{eventType}")
    public ResponseEntity<List<AuditEvent>> getEventsByType(@PathVariable String eventType) {
        return ResponseEntity.ok(service.getEventsByType(eventType));
    }

    // Search by user
    @GetMapping("/events/user/{userId}")
    public ResponseEntity<List<AuditEvent>> getEventsByUser(@PathVariable String userId) {
        return ResponseEntity.ok(service.getEventsByUser(userId));
    }

    // Search by status
    @GetMapping("/events/status/{status}")
    public ResponseEntity<List<AuditEvent>> getEventsByStatus(@PathVariable String status) {
        return ResponseEntity.ok(service.getEventsByStatus(status));
    }

    // Search by severity
    @GetMapping("/events/severity/{severity}")
    public ResponseEntity<List<AuditEvent>> getEventsBySeverity(@PathVariable String severity) {
        return ResponseEntity.ok(service.getEventsBySeverity(severity));
    }

    // Search by date range
    @GetMapping("/events/search")
    public ResponseEntity<List<AuditEvent>> searchByDateRange(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime start,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime end) {
        return ResponseEntity.ok(service.getEventsByDateRange(start, end));
    }

    // Get statistics
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStatistics() {
        return ResponseEntity.ok(service.getStatistics());
    }
}