package cybershield.dao;

import java.util.List;

/**
 * GenericDAO — A generic interface that defines standard CRUD operations.
 * Demonstrates ABSTRACTION: this interface hides how data is stored (MySQL, file, etc.).
 * Every DAO class implements this interface, which is POLYMORPHISM (same method names, different SQL).
 *
 * @param <T> the model type (e.g. Threat, Incident, BlockedIP, LogEntry)
 */
public interface GenericDAO<T> {

    /** Inserts a new record into the database. */
    void add(T item);

    /** Updates an existing record in the database. */
    void update(T item);

    /** Deletes a record by its primary key id. */
    void delete(int id);

    /** Returns a single record by its primary key id, or null if not found. */
    T getById(int id);

    /** Returns all records from the table. */
    List<T> getAll();
}
