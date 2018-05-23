package com.powermock.employee;

public class EmployeeService {

	public int getEmployeeCount() {
		return Employee.count();
	}

	public boolean giveIncrementToAllEmployeesOf(int percentage) {
		try {
			Employee.giveIncrementOf(percentage);
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	public void saveEmployee(Employee employee) {
		if (employee.isNew()) {
			employee.create();
			return;
		}
		employee.update();
	}

}
