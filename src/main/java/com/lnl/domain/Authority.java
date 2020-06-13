package com.lnl.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "authority" ,schema = "lnlauth2")
public class Authority {

	@Id
	@NotNull
	@Size(min = 0, max = 50)
	private String name;

}
