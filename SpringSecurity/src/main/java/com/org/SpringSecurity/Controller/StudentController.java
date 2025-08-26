package com.org.SpringSecurity.Controller;

import com.org.SpringSecurity.Model.Student;
import com.org.SpringSecurity.Service.StudentService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/students")
public class StudentController {

    @Autowired
    private StudentService studentService;

    @GetMapping("/csrfToken")
    public CsrfToken getcsrfToken(HttpServletRequest request){
        return (CsrfToken) request.getAttribute("_csrf");
    }

    @PostMapping("/")
    public Student createStudent(@RequestBody Student student) {
        System.out.println("Received student: " + student);
        return studentService.saveStudent(student);
    }

    @GetMapping("/")
    public List<Student> getAllStudents() {
        return studentService.getAllStudents();
    }

    @GetMapping("/{id}")
    public Optional<Student> getStudentById(@PathVariable int id) {
        return studentService.getStudentById(id);
    }

    @DeleteMapping("/{id}")
    public String deleteStudent(@PathVariable int id) {
        studentService.deleteStudent(id);
        return "Student with ID " + id + " has been deleted.";
    }
}
