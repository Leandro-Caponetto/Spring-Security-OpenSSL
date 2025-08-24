package com.spring.security.services.models.validation;

import com.spring.security.persistence.entities.UserEntity;
import com.spring.security.services.models.dtos.ResponseDTO;

public class UserValidation {

    public ResponseDTO validate(UserEntity user) {
        ResponseDTO response = new ResponseDTO();
        response.setNumOfErrors(0);
        StringBuilder messages = new StringBuilder();

        // Validación firstName
        if (user.getFirstName() == null || user.getFirstName().isEmpty()) {
            response.setNumOfErrors(response.getNumOfErrors() + 1);
            messages.append("El campo firstName es requerido. ");
        } else if (user.getFirstName().length() < 3 || user.getFirstName().length() > 15) {
            response.setNumOfErrors(response.getNumOfErrors() + 1);
            messages.append("El campo firstName debe tener entre 3 y 15 caracteres. ");
        }

        // Validación lastName
        if (user.getLastName() == null || user.getLastName().isEmpty()) {
            response.setNumOfErrors(response.getNumOfErrors() + 1);
            messages.append("El campo lastName es requerido. ");
        } else if (user.getLastName().length() < 3 || user.getLastName().length() > 30) {
            response.setNumOfErrors(response.getNumOfErrors() + 1);
            messages.append("El campo lastName debe tener entre 3 y 30 caracteres. ");
        }

        // Validación email
        if (user.getEmail() == null || user.getEmail().isEmpty()) {
            response.setNumOfErrors(response.getNumOfErrors() + 1);
            messages.append("El campo email es requerido. ");
        } else if (!user.getEmail().matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$")) {
            response.setNumOfErrors(response.getNumOfErrors() + 1);
            messages.append("El campo email debe ser válido. ");
        }

        // Validación password
        if (user.getPassword() == null || user.getPassword().isEmpty()) {
            response.setNumOfErrors(response.getNumOfErrors() + 1);
            messages.append("El campo password es requeridorrrrrrrr. ");
        } else {
            if (user.getPassword().length() < 8 || user.getPassword().length() > 16) {
                response.setNumOfErrors(response.getNumOfErrors() + 1);
                messages.append("La contraseña debe tener entre 8 y 16 caracteres. ");
            }
            if (!user.getPassword().matches(".*\\d.*")) {
                response.setNumOfErrors(response.getNumOfErrors() + 1);
                messages.append("La contraseña debe contener al menos un número. ");
            }
            if (!user.getPassword().matches(".*[a-z].*")) {
                response.setNumOfErrors(response.getNumOfErrors() + 1);
                messages.append("La contraseña debe contener al menos una letra minúscula. ");
            }
            if (!user.getPassword().matches(".*[A-Z].*")) {
                response.setNumOfErrors(response.getNumOfErrors() + 1);
                messages.append("La contraseña debe contener al menos una letra mayúscula. ");
            }
        }

        if (response.getNumOfErrors() == 0) {
            response.setMessage("Validación exitosa.");
        } else {
            response.setMessage(messages.toString().trim());
        }

        return response;
    }
}
