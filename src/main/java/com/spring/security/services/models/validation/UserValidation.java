package com.spring.security.services.models.validation;

import com.spring.security.persistence.entities.UserEntity;
import com.spring.security.services.models.dtos.ResponseDTO;

public class UserValidation {

  public ResponseDTO validate(UserEntity user) {
      ResponseDTO response = new ResponseDTO();
      response.setNumOfErrors(0);

      if(user.getFirstName() == null || user.getFirstName().isEmpty()
              || user.getFirstName().length() < 3 ||
       user.getFirstName().length() > 15) {
          response.setNumOfErrors(response.getNumOfErrors() + 1);
          response.setMessage("El campo firstName es requerido, debe tener entre 3 y 15 caracteres.");
      } else if (user.getLastName() == null || user.getLastName().isEmpty()  ||
              user.getLastName().length() < 3 ||
              user.getLastName().length() > 30) {
          response.setNumOfErrors(response.getNumOfErrors() + 1);
          response.setMessage("El campo lastName es requerido, debe tener entre 3 y 30 caracteres.");
      } else if (user.getEmail() == null || user.getEmail().isEmpty() ||
              !user.getEmail().matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$")) {
          response.setNumOfErrors(response.getNumOfErrors() + 1);
          response.setMessage("El campo email es requerido y debe ser válido.");
      } else if (user.getPassword() == null || user.getPassword().isEmpty() ||
              user.getPassword().length() < 8 ||
              user.getPassword().length() > 16 ||
              !user.getPassword().matches("^(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,16}$")) {
          response.setNumOfErrors(response.getNumOfErrors() + 1);
          response.setMessage("Password is required.");
      } else {
          response.setMessage("La contraseña debe tener entre 8 y 16 caracteres, al menos un número, una minúscula y una mayúscula.");
      }
      return response;
  }
}
