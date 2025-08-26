package com.org.SpringSecurity.Service;

import com.org.SpringSecurity.Model.Student;
import com.org.SpringSecurity.Repository.StudentRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class StudentService {

    @Autowired
    private StudentRepository studentRepository;

    public Student saveStudent(Student student) {
        System.out.println("Saving student: " + student);
        return studentRepository.save(student);
    }

    public List<Student> getAllStudents() {
        return studentRepository.findAll();
    }

    public Optional<Student> getStudentById(int id) {
        return studentRepository.findById(id);
    }

    public void deleteStudent(int id) {
        studentRepository.deleteById(id);
    }
}

