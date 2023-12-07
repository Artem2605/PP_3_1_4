package ru.kata.spring.boot_security.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.service.RoleServiceImpl;
import ru.kata.spring.boot_security.demo.service.UserServiceImpl;
import javax.validation.Valid;
import java.security.Principal;

@Controller
public class AdminController {

    private final UserServiceImpl userService;
    private final RoleServiceImpl roleService;

    @Autowired
    public AdminController(UserServiceImpl userService, RoleServiceImpl roleService) {
        this.userService = userService;
        this.roleService = roleService;
    }

    @GetMapping("/admin")
    public String goAdminPageListOfUsers(Principal principal, Model model) {
        model.addAttribute("entryUser", userService.findByUsername(principal.getName()));
        model.addAttribute("allUsers", userService.getListOfUsers());
        model.addAttribute("allRoles", roleService.getListOfRoles());
        model.addAttribute("newUser", new User());
        return "adminPage";
    }

    @PostMapping("/admin/addUser")
    public String createUser(@ModelAttribute("newUser") @Valid User user,
                             BindingResult bindingResult) {
        if (!bindingResult.hasErrors() && !userService.saveUser(user)) {
            return "errPage";
        }
        return "redirect:/admin";
    }

    @PostMapping("/admin/updateUser")
    public String updateUser(@ModelAttribute("user") @Valid User user,
                             BindingResult bindingResult) {
        if (!bindingResult.hasErrors() && !userService.updateUser(user)) {
            return "errPage";
        }
        return "redirect:/admin";
    }

    @PostMapping("/admin/deleteUser")
    public String deleteUser(@RequestParam(value = "id") Long id) {
        userService.deleteUserById(id);
        return "redirect:/admin";
    }
}